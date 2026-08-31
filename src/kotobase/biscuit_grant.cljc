(ns kotobase.biscuit-grant
  "What a kotobase-issued Biscuit says, once its chain has been checked.

  One implementation, two deployables. `authn` mints these and layers
  tenant/role policy on top; the API gateway only needs to know whether a
  bearer may write, and must be able to decide that **without any secret** --
  that is the whole reason the credential is a Biscuit and not a shared
  string. Both read the token through here, so there is no second answer to
  drift away from the first.

  Deliberately narrower than `authn.biscuit/verify`: no roles, no tenants,
  no viewer. Signature chain, expiry, holder, scopes. A caller that needs
  more asks for more; a caller that needs less must not have to import a
  policy it does not enforce.

  No crypto and no clock: `verify-fn` and `now-ms` are injected."
  (:require [authority.scope :as authority-scope]
            [biscuit.authority :as biscuit-authority]
            [biscuit.wire :as wire]
            [clojure.string :as str]))

(def permission-prefix "kotoba://can/")
(def graph-prefix "kotoba://graph/")
(def tenant-prefix "kotoba://tenant/")
(def repository-prefix "kotoba://repository/")

(def object-prefix
  "One archived object, by CID. The unit an agent should be handed.

  `kotoba://graph/…` scopes a database and `kotoba://tenant/…` an account;
  neither says which bytes. An agent asked to archive one artifact needs
  authority over that artifact and nothing else, and Biscuit can express
  that without the issuer being present — which is the property that makes
  least privilege per agent practical rather than aspirational."
  "kotoba://object/")

(defn decode-base64url
  "base64url without padding → octets, or nil. Returns nil rather than
  throwing: the input is an untrusted header."
  [s]
  (when (and (string? s) (seq s) (re-matches #"[A-Za-z0-9_-]+" s))
    (try
      (let [padded (str s (apply str (repeat (mod (- 4 (mod (count s) 4)) 4) "=")))
            raw #?(:cljs (js/atob (-> padded (str/replace "-" "+") (str/replace "_" "/")))
                   :clj (String. (.decode (java.util.Base64/getDecoder)
                                          ^String (-> padded (str/replace "-" "+")
                                                      (str/replace "_" "/")))
                                 "ISO-8859-1"))]
        (mapv #(bit-and (int #?(:cljs (.charCodeAt raw %) :clj (.charAt ^String raw %))) 0xFF)
              (range (count raw))))
      (catch #?(:clj Exception :cljs :default) _ nil))))

(defn header-token
  "The token out of an `Authorization: Biscuit …` header, or nil.

  Case-insensitive on the scheme, because a header is written by whoever
  is calling and `biscuit` is as valid as `Biscuit`."
  [authorization]
  (when (string? authorization)
    (let [[scheme value] (str/split (str/trim authorization) #"\s+" 2)]
      (when (and value (= "biscuit" (str/lower-case (str scheme))))
        (str/trim value)))))

(defn grant
  "Verify and read. Returns `{:ok? true :scopes :holder :expires-at
  :permissions :graphs :tenants :blocks}` or `{:ok? false :reason …}`.

  Every failure has a NAMED reason. A verifier that answers false without
  saying why sends whoever reads the log looking in the wrong place, and
  the reasons here are all things that mean different repairs: a malformed
  header is a client bug, a bad signature is an attack or a key rotation,
  and an expired token is neither."
  [encoded {:keys [root-public-key verify-fn now-ms]}]
  (cond
    (not (ifn? verify-fn)) {:ok? false :reason :verify-fn-required}
    (not (and (sequential? root-public-key) (= 32 (count root-public-key))))
    {:ok? false :reason :root-public-key-required}
    (not (number? now-ms)) {:ok? false :reason :now-required}
    :else
    (if-let [octets (decode-base64url encoded)]
      (let [decoded (try (wire/decode-token octets)
                         (catch #?(:clj Exception :cljs :default) _ nil))]
        (if (nil? decoded)
          {:ok? false :reason :malformed-token}
          (let [verified (try (wire/verify decoded (vec root-public-key) verify-fn)
                              (catch #?(:clj Exception :cljs :default) _ nil))]
            (if-not (:ok? verified)
              {:ok? false :reason :bad-signature}
              (let [model (wire/token->model decoded)
                    first-scopes (vec (keep (fn [[p v]] (when (= 'scope p) v))
                                            (get-in model [:biscuit/blocks 0 :block/facts])))
                    g (biscuit-authority/->grant model {:scopes first-scopes})
                    ;; `->grant` hands back PARSED scopes -- `["kotoba" "can"
                    ;; "data:write"]`, not the URI it was written as. Reading
                    ;; those as strings finds no permissions at all and the
                    ;; token verifies into an empty grant: every refusal test
                    ;; still passes, and only the acceptance test notices.
                    ;; `authority.scope/sorted` renders them back, which is
                    ;; why authn's verify has the same call.
                    scopes (set (authority-scope/sorted (:grant/scopes g)))
                    expiry (:grant/expires g)
                    exp-ms (when (string? expiry)
                             #?(:cljs (let [n (js/Date.parse expiry)]
                                        (when (js/Number.isFinite n) n))
                                :clj (try (.toEpochMilli (java.time.Instant/parse expiry))
                                          (catch Exception _ nil))))
                    strip (fn [prefix]
                            (set (keep #(when (and (string? %) (str/starts-with? % prefix))
                                          (subs % (count prefix)))
                                       scopes)))]
                (cond
                  (nil? exp-ms) {:ok? false :reason :no-expiry}
                  (<= exp-ms now-ms) {:ok? false :reason :expired :expires-at exp-ms}
                  :else
                  {:ok? true
                   :scopes scopes
                   :holder (:grant/holder g)
                   :expires-at exp-ms
                   :permissions (strip permission-prefix)
                   :graphs (strip graph-prefix)
                   :tenants (strip tenant-prefix)
                   :repositories (strip repository-prefix)
                   :objects (strip object-prefix)
                   :blocks (:blocks verified)}))))))
      {:ok? false :reason :malformed-token})))

(defn permits?
  "Does this grant carry `permission`?

  Attenuation can only ever REMOVE scopes, so asking the grant is asking
  the narrowest block that survived. There is no widening to guard against
  here -- that property is the format's, not this function's."
  [grant permission]
  (boolean (and (:ok? grant) (contains? (:permissions grant) permission))))

(defn permits-object?
  "Does this grant reach the object at `cid`?

  **A grant with no object scope reaches every object.** That is not a hole
  left open: it is what every token minted before this prefix existed looks
  like, and ADR-2608262600 chose addition over rotation precisely so that
  holders are not silently locked out by a change they did not ask for. A
  grant that carries one or more object scopes must name this one.

  So the narrowing is done by the holder, offline: take a broad token, append
  a block carrying `kotoba://object/<cid>`, hand that to the agent. The issuer
  is never consulted, and the agent cannot widen it back — attenuation only
  ever removes.

  Absent `cid` answers false rather than true. A caller that does not know
  which object it is checking has not asked a question this can answer, and
  the safe direction for an unanswerable authorization question is no."
  [grant cid]
  (boolean (and (:ok? grant)
                (string? cid)
                (seq cid)
                (let [objects (:objects grant)]
                  (or (empty? objects) (contains? objects cid))))))

(defn permits-repository?
  "Repository authority is opt-in. Unlike the legacy object scope, absence is
  never broad authority: private Git is a new surface, so no old token needs a
  compatibility widening."
  [grant rid]
  (boolean (and (:ok? grant)
                (string? rid)
                (seq rid)
                (contains? (:repositories grant) rid))))

(defn single-tenant
  "The one tenant named by a repository capability, or nil. A multi-tenant
  token leaves the storage namespace ambiguous and therefore fails closed."
  [grant]
  (let [tenants (:tenants grant)]
    (when (= 1 (count tenants)) (first tenants))))
