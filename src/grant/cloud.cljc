(ns grant.cloud
  "The two remote authorities ADR-0041 names — kotobase for storage,
  murakumo for inference — expressed as decisions.

  Contract: `resources/aiueos/cloud_contract.edn`. Nothing here opens a socket.
  A plan is a request this policy would allow, and an admission is a verdict
  about a response a provider already received. Transport is provider
  mechanism, exactly as in `grant.ota`.

  ## The holes this namespace closes

  **A CID is a claim about bytes, and a response is bytes.** `plan-block-read`
  carries the digest the CID commits to, and `admit-block` refuses a response
  whose observed digest differs. A provider that cannot say what it hashed gets
  `:digest-missing` — silence is not a pass, because a check that could not run
  must not return the value of a check that ran and found nothing wrong.

  **kotobase's `PUT /ipfs/:cid` accepts raw CIDv1 only** (root ADR-2608148200).
  An object whose identity CID is dag-cbor is archived under the *raw* CID of
  the same bytes. Refusing that before the request is the difference between a
  decision and a collected 400.

  **The model alias is a redirect.** `murakumo-main` resolves through a mutable
  KV entry to an endpoint, so an allowlist that admitted `api.murakumo.cloud`
  would otherwise authorise whatever host that entry names next. `admit-model`
  re-checks the resolved endpoint against the same allowlist that admitted the
  resolver.

  **`alias-for` is not the model to request.** Sending the concrete id the alias
  currently points at freezes this machine at whatever was serving the moment it
  resolved — precisely what root ADR-2607173100 forbids. The request carries the
  alias; an override that equals `alias-for` is refused rather than honoured.

  ## What this does not do

  It does not put aiueos on the network. The bare-metal profile has no DNS, no
  TLS and no HTTP client (ADR-0041's gap ledger, steps 1–5); this is the
  decision layer those steps will be wired underneath, and it is checkable
  before any of them exist."
  (:require [grant.net :as net]
            [grant.policy :as policy]
            [clojure.string :as str]))

(def default-config
  "Origins and the alias name. Overridable per policy map — a deployment that
  reaches a different kotobase or a different murakumo changes these, not the
  code. `:model-alias` is a name, never a model id."
  {:aiueos.cloud/storage-origin   "https://kotobase.net"
   :aiueos.cloud/inference-origin "https://api.murakumo.cloud"
   :aiueos.cloud/model-alias      "murakumo-main"})

(def deny-reasons
  "Reasons this namespace produces. `grant.net`'s own denial passes through
  `perform` unchanged."
  #{:cid-unparsable :cid-not-raw :cid-not-sha256
    :origin-not-allowed :insecure-transport :plan-not-allowed
    :response-not-ok :digest-missing :digest-mismatch
    :alias-unresolved :resolved-endpoint-not-allowed
    :model-is-alias-target :messages-missing
    :no-trust-anchors :peer-unmeasured :peer-not-pinned})

(defn- cfg [policy k]
  (get policy k (get default-config k)))

(defn- deny [reason extra]
  (merge {:aiueos/decision :deny :aiueos.cloud/reason reason} extra))

(defn- allow [extra]
  (merge {:aiueos/decision :allow} extra))

(defn allowed?
  "Whether DECISION is an allow. Every plan and admission answers this."
  [decision]
  (= :allow (:aiueos/decision decision)))

;; ── CIDv1, narrowly ────────────────────────────────────────────────────────
;;
;; aiueos is dependency-minimal by invariant (README: deps.edn carries
;; `security` + Chicory only; enforcement layers import aiueos, never the
;; reverse). `kotoba-lang/io-multiformats` is the workspace authority for this
;; format and is where a general codec belongs; what is inlined here is the one
;; shape kotobase and the IPFS gateways emit — multibase base32-lower CIDv1 —
;; and it refuses everything else rather than guessing.

(def ^:private base32-lower "abcdefghijklmnopqrstuvwxyz234567")

(def ^:private base32-index
  (into {} (map-indexed (fn [i c] [(str c) i])) base32-lower))

(def ^:private hex-digits "0123456789abcdef")

(defn- base32-decode
  "RFC 4648 base32, lowercase, unpadded → vector of unsigned bytes, or nil.
  Leftover bits must be zero: a trailing partial group with data in it is a
  malformed encoding, not a truncated one to be tolerated."
  [s]
  (loop [i 0, acc 0, bits 0, out []]
    (if (= i (count s))
      (when (and (< bits 5) (zero? acc)) out)
      (if-let [v (get base32-index (subs s i (inc i)))]
        (let [acc (bit-or (bit-shift-left acc 5) v)
              bits (+ bits 5)]
          (if (>= bits 8)
            (let [rest-bits (- bits 8)]
              (recur (inc i)
                     (bit-and acc (dec (bit-shift-left 1 rest-bits)))
                     rest-bits
                     (conj out (bit-and (unsigned-bit-shift-right acc rest-bits) 0xff))))
            (recur (inc i) acc bits out)))
        nil))))

(defn- hex-of [bytes]
  (str/join (mapcat (fn [b]
                      [(nth hex-digits (unsigned-bit-shift-right b 4))
                       (nth hex-digits (bit-and b 0xf))])
                    bytes)))

(def ^:private codec-names
  "Only the single-byte codes. A codec whose varint continues into a second
  byte would shift every field after it, so `cid-info` refuses that string
  outright rather than reading the multihash out of the wrong offset."
  {0x55 :raw 0x70 :dag-pb 0x71 :dag-cbor})

(def ^:private sha2-256 0x12)

(defn cid-info
  "Decode CID. Returns `{:version 1 :codec <int> :codec-name <kw> :multihash
  <int> :digest-hex <string-or-nil>}`, or nil when the string is not a
  base32-lower CIDv1 at all.

  A non-sha2-256 multihash decodes to a nil `:digest-hex` rather than a nil
  result: the caller then denies with `:cid-not-sha256`, which says something
  different from `:cid-unparsable`."
  [cid]
  (let [s (str cid)]
    (when (and (> (count s) 1) (str/starts-with? s "b"))
      (when-let [bytes (base32-decode (subs s 1))]
        (when (and (>= (count bytes) 4)
                   (= 1 (nth bytes 0))
                   (< (nth bytes 1) 0x80))
          (let [codec (nth bytes 1)
                mh (nth bytes 2)
                mh-len (nth bytes 3)
                digest (subvec bytes 4)]
            {:version 1
             :codec codec
             :codec-name (get codec-names codec :unknown)
             :multihash mh
             :digest-hex (when (and (= mh sha2-256)
                                    (= mh-len 32)
                                    (= (count digest) 32))
                           (hex-of digest))}))))))

;; ── who is on the other end ────────────────────────────────────────────────
;;
;; A cloud-premised machine's whole authority story rests on reaching the right
;; host. Until now that rested on the platform's default trust store: several
;; hundred anchors chosen by whoever packaged the runtime, any one of which
;; could vouch for anything. That is a reasonable default for a browser, which
;; must reach hosts nobody enumerated in advance. It is the wrong default here,
;; because this machine talks to exactly two authorities and both are known
;; before it boots.

(defn trust-anchors
  "The SPKI SHA-256 hex pins this policy will accept, as a set. Empty means the
  operator has not said, which is not the same as \"anything\"."
  [policy]
  (set (map #(str/lower-case (str %)) (:aiueos.cloud/trust-anchors policy))))

(defn anchors-declared?
  "Whether this policy names any peer key at all. Checked before the socket,
  so a machine with no anchors does not open a connection it could not have
  judged."
  [policy]
  (boolean (seq (trust-anchors policy))))

(defn admit-peer
  "Judge the peer a connection reached. PEER is `{:spki-sha256 <hex>}` — the
  SHA-256 of the leaf certificate's SubjectPublicKeyInfo, measured by the
  provider.

  The pin is over the **key**, not the certificate, so an authority that
  renews its certificate with the same key keeps working and one that changes
  key does not — which is the event worth noticing.

  Three refusals, deliberately distinct: nothing was declared, nothing was
  measured, and what was measured is not what was declared. Only the third is
  an attack; the first two are a machine that must not proceed as though it
  had checked."
  [policy peer]
  (let [pins (trust-anchors policy)
        measured (str/lower-case (str (:spki-sha256 peer)))]
    (cond
      (empty? pins) (deny :no-trust-anchors {})
      (str/blank? measured) (deny :peer-unmeasured {})
      (not (contains? pins measured))
      (deny :peer-not-pinned {:aiueos.cloud/observed-spki measured})
      :else (allow {:aiueos.cloud/peer-spki measured}))))

;; ── storage: kotobase ──────────────────────────────────────────────────────

(defn- join-url [origin path]
  (str (if (str/ends-with? origin "/") (subs origin 0 (dec (count origin))) origin)
       path))

(defn- insecure-permitted?
  "Whether URL sits under an origin the operator explicitly marked as allowed
  to be plaintext. The escape hatch exists because a loopback test server has
  no certificate, and it is spelled out in policy so it is visible in the
  deployment rather than hidden in the code."
  [policy url]
  (boolean (some #(str/starts-with? url (str %))
                 (:aiueos.cloud/allow-insecure-origins policy))))

(defn- secure? [policy url]
  (or (str/starts-with? url "https://") (insecure-permitted? policy url)))

(defn- with-allowed-url
  "Gate URL through TLS and the same allowlist every provider shares, then hand
  it to BUILD. One place, so a new request kind cannot forget either check.

  `grant.policy/net-url-allowed?` matches on host: it strips the scheme and the
  port before comparing, so an entry admitting `kotobase.net` admits plaintext
  to `kotobase.net` just as readily. For a machine whose storage and inference
  authorities are both remote, plaintext is not a degraded mode, it is a
  different threat model — so the transport is checked here rather than left to
  whoever wrote the allowlist entry."
  [policy url build]
  (cond
    (not (secure? policy url)) (deny :insecure-transport {:aiueos.cloud/url url})
    (not (policy/net-url-allowed? policy url)) (deny :origin-not-allowed {:aiueos.cloud/url url})
    :else (allow (build url))))

(defn plan-block-read
  "Plan a block read of CID from the storage authority. Any codec may be read;
  the plan carries the digest the CID commits to so `admit-block` can check the
  bytes that come back."
  [policy cid]
  (if-let [info (cid-info cid)]
    (if-let [digest (:digest-hex info)]
      (with-allowed-url policy (join-url (cfg policy :aiueos.cloud/storage-origin)
                                         (str "/ipfs/" cid))
        (fn [url] {:aiueos.cloud/request {:method :get :url url}
                   :aiueos.cloud/cid (str cid)
                   :aiueos.cloud/codec (:codec-name info)
                   :aiueos.cloud/expect-digest digest}))
      (deny :cid-not-sha256 {:aiueos.cloud/cid (str cid)
                             :aiueos.cloud/multihash (:multihash info)}))
    (deny :cid-unparsable {:aiueos.cloud/cid (str cid)})))

(defn plan-block-write
  "Plan a block write of CID. `PUT /ipfs/:cid` takes raw CIDv1 only, so a
  dag-cbor identity CID is refused here rather than at the server: the Location
  of those bytes is the raw CID of the same bytes, and the caller has to say
  which one it means (root ADR-2608148200)."
  [policy cid]
  (if-let [info (cid-info cid)]
    (cond
      (not= :raw (:codec-name info))
      (deny :cid-not-raw {:aiueos.cloud/cid (str cid)
                          :aiueos.cloud/codec (:codec-name info)})

      (nil? (:digest-hex info))
      (deny :cid-not-sha256 {:aiueos.cloud/cid (str cid)
                             :aiueos.cloud/multihash (:multihash info)})

      :else
      (with-allowed-url policy (join-url (cfg policy :aiueos.cloud/storage-origin)
                                         (str "/ipfs/" cid))
        (fn [url] {:aiueos.cloud/request {:method :put :url url}
                   :aiueos.cloud/cid (str cid)
                   :aiueos.cloud/codec :raw
                   :aiueos.cloud/expect-digest (:digest-hex info)})))
    (deny :cid-unparsable {:aiueos.cloud/cid (str cid)})))

(defn admit-block
  "Judge a RESPONSE against the PLAN that asked for it. RESPONSE is
  `{:status <int> :digest-hex <string>}` — the provider hashed the bytes it
  received, because this namespace does not hash (`grant.signing/sha256-hex`
  is JVM-only, and a second canonicaliser would be its own hazard).

  A response with no `:digest-hex` is denied. The provider not having measured
  is a different fact from the bytes being right, and only one of them is a
  pass."
  [plan response]
  (cond
    (not (allowed? plan))
    (deny :plan-not-allowed {:aiueos.cloud/plan-reason (:aiueos.cloud/reason plan)})

    (not= 200 (:status response))
    (deny :response-not-ok {:aiueos.cloud/status (:status response)
                            :aiueos.cloud/cid (:aiueos.cloud/cid plan)})

    (str/blank? (str (:digest-hex response)))
    (deny :digest-missing {:aiueos.cloud/cid (:aiueos.cloud/cid plan)})

    (not= (:aiueos.cloud/expect-digest plan) (:digest-hex response))
    (deny :digest-mismatch {:aiueos.cloud/cid (:aiueos.cloud/cid plan)
                            :aiueos.cloud/expect-digest (:aiueos.cloud/expect-digest plan)
                            :aiueos.cloud/observed-digest (:digest-hex response)})

    :else
    (allow {:aiueos.cloud/cid (:aiueos.cloud/cid plan)
            :aiueos.cloud/digest (:digest-hex response)})))

;; ── inference: murakumo ────────────────────────────────────────────────────

(defn plan-model-resolve
  "Plan the alias lookup. The alias name is configuration; the model id it
  points at is never written down here."
  [policy]
  (let [alias (cfg policy :aiueos.cloud/model-alias)]
    (with-allowed-url policy (join-url (cfg policy :aiueos.cloud/inference-origin)
                                       (str "/infer/models/" alias))
      (fn [url] {:aiueos.cloud/request {:method :get :url url}
                 :aiueos.cloud/alias alias}))))

(defn admit-model
  "Judge the alias RESOLUTION — `{:endpoint <url> :alias-for <model-id>}`.

  The resolved endpoint is re-checked against the allowlist. The entry is
  mutable and lives outside this machine, so admitting the resolver is not
  admitting whatever the resolver names."
  [policy resolution]
  (let [alias (cfg policy :aiueos.cloud/model-alias)
        endpoint (str (:endpoint resolution))]
    (cond
      (str/blank? endpoint)
      (deny :alias-unresolved {:aiueos.cloud/alias alias})

      (not (secure? policy endpoint))
      (deny :insecure-transport {:aiueos.cloud/alias alias
                                 :aiueos.cloud/url endpoint})

      (not (policy/net-url-allowed? policy endpoint))
      (deny :resolved-endpoint-not-allowed {:aiueos.cloud/alias alias
                                            :aiueos.cloud/url endpoint})

      :else
      (allow {:aiueos.cloud/model {:alias alias
                                   :endpoint endpoint
                                   :alias-for (:alias-for resolution)}}))))

(defn plan-inference
  "Plan a request against the admitted MODEL. OPTS carries `:messages` and may
  carry `:model-override`.

  The request's model is the alias. An override is honoured — an operator
  pinning a specific model is legitimate, and is the first step of the root
  resolution order — except for the one override that never is: the id the
  alias currently resolves to. Pinning to `alias-for` looks like precision and
  is a snapshot, and it stops this machine following the fleet."
  [policy model opts]
  (let [messages (:messages opts)
        override (:model-override opts)
        url (join-url (:endpoint model) "/v1/messages")]
    (cond
      (empty? messages)
      (deny :messages-missing {:aiueos.cloud/alias (:alias model)})

      (and (some? override) (= override (:alias-for model)))
      (deny :model-is-alias-target {:aiueos.cloud/alias (:alias model)
                                    :aiueos.cloud/model-override override})

      :else
      (with-allowed-url policy url
        (fn [url] {:aiueos.cloud/request
                   {:method :post
                    :url url
                    :body (cond-> {:model (or override (:alias model))
                                   :messages (vec messages)}
                            (:max-tokens opts) (assoc :max_tokens (:max-tokens opts)))}
                   :aiueos.cloud/alias (:alias model)
                   :aiueos.cloud/pinned? (some? override)})))))

;; ── performing a plan ──────────────────────────────────────────────────────

(defn perform
  "Run an allowed PLAN's request through `grant.net/guarded-fetch`, so the URL
  is checked again at call time by the same function every other provider
  calls. A denied plan never reaches FETCH-FN, and neither does a plan whose
  URL stopped being allowed between planning and now."
  [policy plan fetch-fn]
  (if (allowed? plan)
    (net/guarded-fetch policy (get-in plan [:aiueos.cloud/request :url])
                       (fn [url] (fetch-fn (assoc (:aiueos.cloud/request plan) :url url))))
    {:ok? false
     :aiueos.cloud/denied (:aiueos.cloud/reason plan)}))
