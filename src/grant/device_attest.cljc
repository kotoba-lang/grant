(ns grant.device-attest
  "The possession proof a device signs during enrolment: what exactly gets
  signed, and what the device does with each answer.

  `grant.enroll` decides whether a claim is admitted. This decides the one
  thing that has to be byte-identical on both sides of the wire, because a
  device and a control plane that disagree about it produce a signature that
  verifies nowhere and a device that can never be claimed.

  ## Why not the bare nonce

  Signing the nonce alone proves possession of *a* key at *some* point, which
  is not the question being asked. This binds three more things:

  - the **device**, so a proof made by one cannot be replayed for another;
  - the **endpoint**, so a proof harvested by one enrolment service cannot be
    presented to a different one;
  - the **purpose**, so an enrolment proof cannot be lifted into another
    protocol that happens to sign the same shape.

  (`aiueos.provider.device` wrote that reasoning down first, for a document
  form built by `grant.key-lifecycle/document-bytes`. That canonicaliser is
  JVM-only and depends on `pr-str` printing a map in insertion order, which
  this workspace has already recorded as breaking silently past eight keys --
  not a thing to put a signature check on across two runtimes. So the same
  bindings are carried by an explicit byte string instead.)

  ## Why the framing is checked rather than assumed

  The fields are newline-terminated, so a field that CONTAINS a newline could
  frame itself as two fields and let two different tuples produce identical
  bytes. `signing-input` refuses such a field instead of escaping it: an
  enrolment nonce or endpoint with a newline in it is a bug upstream, and
  quietly accepting it would move the ambiguity somewhere harder to see.

  Pure: strings in, a string or a named refusal out. No I/O, no crypto -- the
  caller signs the bytes and the verifier checks them."
  (:require [clojure.string :as str]))

(def attest-domain
  "The domain separator. Changing it invalidates every signature made under
  the old one, which is what a version bump is for."
  "aiueos-device-attest-v1")

(def field-separator "\n")

(def ^:private framed-fields [:did :endpoint :nonce])

(defn signing-input-problem
  "Why these fields cannot be framed unambiguously, or nil.

  Named individually: `:field-blank` and `:field-contains-separator` are
  different bugs in different places, and one reason for both would send the
  reader to the wrong one."
  [fields]
  (let [vs (map #(get fields %) framed-fields)]
    (cond
      (not (every? string? vs)) :field-not-a-string
      (some str/blank? vs) :field-blank
      (some #(str/includes? % field-separator) vs) :field-contains-separator
      :else nil)))

(defn signing-input
  "The exact string both sides sign over, UTF-8 encoded by the caller.

      aiueos-device-attest-v1\\n<did>\\n<endpoint>\\n<nonce>\\n

  Returns the string, or `{:error <reason>}`. Every field is terminated rather
  than joined, so there is no trailing-empty-field question to answer."
  [{:keys [did endpoint nonce] :as fields}]
  (if-let [problem (signing-input-problem fields)]
    {:error problem}
    (str attest-domain field-separator
         did field-separator
         endpoint field-separator
         nonce field-separator)))

;; ── what the device does with each answer ─────────────────────────────────

(defn plan-poll
  "Given a `GET /challenge` result, what should the device do?

  `status` is nil when the request did not complete. That case is deliberately
  NOT folded into `:idle`: an agent that cannot reach its control plane and one
  that reached it and was told there is nothing to do must not report the same
  thing, or a job that has been failing since the network went down looks like
  a job that is working. Same reason the fleet's snapshot collector refuses to
  push an empty batch.

  Returns `{:action :sign|:idle|:skip|:refuse :reason <kw> ...}`."
  [{:keys [status body now-ms]}]
  (let [challenge (get body "challenge")
        nonce (get body "nonce")
        expires (get body "expiresAtMs")]
    (cond
      (nil? status) {:action :refuse :reason :control-plane-unreachable}

      (= 404 status)
      (if (and (contains? body "challenge") (nil? challenge))
        {:action :idle :reason :no-challenge-pending}
        {:action :refuse :reason :unexpected-not-found})

      (not= 200 status) {:action :refuse :reason :unexpected-status :status status}

      (or (not (string? challenge)) (str/blank? challenge)
          (not (string? nonce)) (str/blank? nonce))
      {:action :refuse :reason :malformed-challenge}

      (not (number? expires)) {:action :refuse :reason :missing-expiry}

      ;; Already dead. Signing it would spend the key on something the server
      ;; will refuse, and report a failure the device caused.
      (and (number? now-ms) (>= now-ms expires))
      {:action :skip :reason :challenge-expired :challenge challenge}

      :else {:action :sign :challenge challenge :nonce nonce :expires-at-ms expires})))

(defn interpret-attest
  "Given a `POST /attest` result, what happened?

  `:rejected` is kept apart from every transport outcome on purpose: it means
  the control plane read a signature this device produced and did not accept
  it, which is a fault in the device's own key handling and not something a
  retry fixes."
  [{:keys [status body]}]
  (cond
    (nil? status) {:outcome :unreachable}
    (and (= 200 status) (true? (get body "verified"))) {:outcome :proved}
    ;; A 200 whose body does not say `true` is not a proof. Checked rather
    ;; than inferred from the status, so the two cannot drift apart.
    (= 200 status) {:outcome :rejected :reason :verified-not-true}
    (= 400 status) {:outcome :rejected :reason :signature-refused}
    (= 404 status) {:outcome :no-challenge}
    (= 410 status) {:outcome :gone}
    :else {:outcome :error :status status}))

(def exit-codes
  "What a one-shot agent run should exit with, so a supervisor can tell the
  outcomes apart without parsing logs.

  `:idle` is 0 -- being told there is nothing to prove is a successful run.
  `:unreachable` is not, and neither is a signature the plane refused."
  {:proved 0
   :idle 0
   :skipped 0
   :rejected 1
   :no-challenge 4
   :gone 4
   :unreachable 3
   :malformed 2
   :error 2})
