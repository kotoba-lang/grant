(ns grant.cloud-test
  (:require [grant.cloud :as cloud]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]))

;; CIDs and digests computed outside the code under test, so the decoder is
;; checked against an independent oracle rather than against itself:
;;   sha256("hello world") = b94d27b9…cde9
;;   sha256("other bytes") = a3ead5ee…a795
(def hello-digest "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
(def raw-cid "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e")
(def cbor-cid "bafyreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e")
(def other-digest "a3ead5eedad5df82318c51685dbc1c147a36d1ff8584fc82de6b08d0bf63a795")

(def policy {:aiueos.policy/net-allow #{"kotobase.net" "api.murakumo.cloud"}})
(def no-network {:aiueos.policy/net-allow #{}})
(def plaintext {:aiueos.policy/net-allow #{"kotobase.net"}
                :aiueos.cloud/storage-origin "http://kotobase.net"})
(def loopback {:aiueos.policy/net-allow #{"127.0.0.1"}
               :aiueos.cloud/storage-origin "http://127.0.0.1:8080"
               :aiueos.cloud/allow-insecure-origins #{"http://127.0.0.1"}})

;; ── the CID says what the bytes must hash to ──────────────────────────────

(deftest a-cid-decodes-to-the-digest-it-commits-to
  (is (= hello-digest (:digest-hex (cloud/cid-info raw-cid))))
  (is (= :raw (:codec-name (cloud/cid-info raw-cid))))
  (is (= :dag-cbor (:codec-name (cloud/cid-info cbor-cid)))
      "same bytes, different codec, same digest")
  (is (= hello-digest (:digest-hex (cloud/cid-info cbor-cid)))))

(deftest a-string-that-is-not-a-base32-cidv1-decodes-to-nothing
  (testing "not multibase base32"
    (is (nil? (cloud/cid-info "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")))
    (is (nil? (cloud/cid-info "zdpuAyvkgEDQm9j"))))
  (testing "not base32 at all"
    (is (nil? (cloud/cid-info "b!!!!"))))
  (testing "truncated"
    (is (nil? (cloud/cid-info "bafk"))))
  (testing "empty and nil"
    (is (nil? (cloud/cid-info "")))
    (is (nil? (cloud/cid-info nil)))))

;; ── reading a block ───────────────────────────────────────────────────────

(deftest a-block-read-carries-the-digest-forward
  (let [plan (cloud/plan-block-read policy raw-cid)]
    (is (cloud/allowed? plan))
    (is (= "https://kotobase.net/ipfs/bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"
           (get-in plan [:aiueos.cloud/request :url])))
    (is (= :get (get-in plan [:aiueos.cloud/request :method])))
    (is (= hello-digest (:aiueos.cloud/expect-digest plan)))))

(deftest any-codec-may-be-read
  (is (cloud/allowed? (cloud/plan-block-read policy cbor-cid))
      "reading a dag-cbor block is ordinary; only PUT is raw-only"))

(deftest an-empty-allowlist-denies-the-read
  (let [plan (cloud/plan-block-read no-network raw-cid)]
    (is (not (cloud/allowed? plan)))
    (is (= :origin-not-allowed (:aiueos.cloud/reason plan)))))

;; ── the transport is part of the decision ─────────────────────────────────

(deftest plaintext-is-refused-even-to-an-allowed-host
  (let [plan (cloud/plan-block-read plaintext raw-cid)]
    (is (= :insecure-transport (:aiueos.cloud/reason plan))
        "the allowlist matches on host and would have admitted this")
    (is (:aiueos.policy/net-allow plaintext))))

(deftest an-operator-can-mark-one-origin-plaintext
  (is (cloud/allowed? (cloud/plan-block-read loopback raw-cid))
      "spelled out in policy, so it is visible in the deployment")
  (is (= :insecure-transport
         (:aiueos.cloud/reason (cloud/plan-block-read
                                (assoc loopback :aiueos.cloud/storage-origin "http://10.0.0.1")
                                raw-cid)))
      "the exemption is one origin, not plaintext in general"))

(deftest an-alias-that-resolves-onto-plaintext-is-refused
  (is (= :insecure-transport
         (:aiueos.cloud/reason (cloud/admit-model policy {:endpoint "http://api.murakumo.cloud"
                                                          :alias-for "qwen3.6-35b-a3b"}))))) 

;; ── who is on the other end ───────────────────────────────────────────────

(def pin-a "af696ad28431887358d6bbc84d02af910ce3fa246dbbcf4264efef8d34a9c083")
(def pin-b (apply str (repeat 64 "b")))
(def pinned (assoc policy :aiueos.cloud/trust-anchors #{pin-a}))

(deftest nothing-declared-is-not-anything
  (is (= :no-trust-anchors (:aiueos.cloud/reason (cloud/admit-peer policy {:spki-sha256 pin-a})))
      "an empty pin set is an operator who has not said, not an operator who said yes")
  (is (false? (cloud/anchors-declared? policy)))
  (is (true? (cloud/anchors-declared? pinned))))

(deftest nothing-measured-is-not-a-pass
  (is (= :peer-unmeasured (:aiueos.cloud/reason (cloud/admit-peer pinned {}))))
  (is (= :peer-unmeasured (:aiueos.cloud/reason (cloud/admit-peer pinned {:spki-sha256 ""})))))

(deftest a-key-that-was-not-named-is-refused
  (let [v (cloud/admit-peer pinned {:spki-sha256 pin-b})]
    (is (= :peer-not-pinned (:aiueos.cloud/reason v)))
    (is (= pin-b (:aiueos.cloud/observed-spki v)) "and it says which key it saw")))

(deftest a-named-key-is-admitted-however-it-is-cased
  (is (cloud/allowed? (cloud/admit-peer pinned {:spki-sha256 pin-a})))
  (is (cloud/allowed? (cloud/admit-peer pinned {:spki-sha256 (str/upper-case pin-a)})))
  (is (cloud/allowed? (cloud/admit-peer (assoc policy :aiueos.cloud/trust-anchors
                                               #{(str/upper-case pin-a)})
                                        {:spki-sha256 pin-a}))))

;; ── judging the response ──────────────────────────────────────────────────

(deftest bytes-that-hash-to-the-cid-are-admitted
  (let [plan (cloud/plan-block-read policy raw-cid)
        v (cloud/admit-block plan {:status 200 :digest-hex hello-digest})]
    (is (cloud/allowed? v))
    (is (= hello-digest (:aiueos.cloud/digest v)))))

(deftest bytes-that-hash-to-something-else-are-refused
  (let [plan (cloud/plan-block-read policy raw-cid)
        v (cloud/admit-block plan {:status 200 :digest-hex other-digest})]
    (is (= :digest-mismatch (:aiueos.cloud/reason v)))
    (is (= hello-digest (:aiueos.cloud/expect-digest v)))
    (is (= other-digest (:aiueos.cloud/observed-digest v)))))

(deftest a-provider-that-did-not-hash-does-not-get-a-pass
  (let [plan (cloud/plan-block-read policy raw-cid)]
    (is (= :digest-missing (:aiueos.cloud/reason (cloud/admit-block plan {:status 200})))
        "no measurement is not the same fact as a good measurement")
    (is (= :digest-missing (:aiueos.cloud/reason
                            (cloud/admit-block plan {:status 200 :digest-hex ""}))))))

(deftest a-non-200-is-refused-before-the-digest-is-consulted
  (let [plan (cloud/plan-block-read policy raw-cid)
        v (cloud/admit-block plan {:status 404 :digest-hex hello-digest})]
    (is (= :response-not-ok (:aiueos.cloud/reason v)))
    (is (= 404 (:aiueos.cloud/status v)))))

(deftest a-denied-plan-cannot-be-used-to-admit-anything
  (let [plan (cloud/plan-block-read no-network raw-cid)
        v (cloud/admit-block plan {:status 200 :digest-hex hello-digest})]
    (is (= :plan-not-allowed (:aiueos.cloud/reason v)))
    (is (= :origin-not-allowed (:aiueos.cloud/plan-reason v))
        "the original refusal is reported, not paraphrased")))

;; ── writing a block: raw only ─────────────────────────────────────────────

(deftest a-raw-cid-may-be-written
  (let [plan (cloud/plan-block-write policy raw-cid)]
    (is (cloud/allowed? plan))
    (is (= :put (get-in plan [:aiueos.cloud/request :method])))))

(deftest a-dag-cbor-identity-cid-is-refused-before-the-request
  (let [plan (cloud/plan-block-write policy cbor-cid)]
    (is (= :cid-not-raw (:aiueos.cloud/reason plan)))
    (is (= :dag-cbor (:aiueos.cloud/codec plan))
        "the Location of those bytes is the raw CID of the same bytes")))

;; ── the alias is a redirect ───────────────────────────────────────────────

(deftest resolving-the-alias-never-names-a-model
  (let [plan (cloud/plan-model-resolve policy)]
    (is (cloud/allowed? plan))
    (is (= "https://api.murakumo.cloud/infer/models/murakumo-main"
           (get-in plan [:aiueos.cloud/request :url])))
    (is (= "murakumo-main" (:aiueos.cloud/alias plan)))))

(deftest an-endpoint-inside-the-allowlist-is-admitted
  (let [v (cloud/admit-model policy {:endpoint "https://api.murakumo.cloud"
                                     :alias-for "qwen3.6-35b-a3b"})]
    (is (cloud/allowed? v))
    (is (= "murakumo-main" (get-in v [:aiueos.cloud/model :alias])))))

(deftest an-endpoint-the-allowlist-never-admitted-is-refused
  (let [v (cloud/admit-model policy {:endpoint "https://attacker.example/infer"
                                     :alias-for "qwen3.6-35b-a3b"})]
    (is (= :resolved-endpoint-not-allowed (:aiueos.cloud/reason v))
        "admitting the resolver is not admitting whatever it names next")))

(deftest an-alias-that-resolves-to-nothing-is-refused
  (is (= :alias-unresolved (:aiueos.cloud/reason (cloud/admit-model policy {}))))
  (is (= :alias-unresolved (:aiueos.cloud/reason (cloud/admit-model policy {:endpoint ""})))))

;; ── the request carries the alias, not the model ──────────────────────────

(def admitted-model
  (:aiueos.cloud/model (cloud/admit-model policy {:endpoint "https://api.murakumo.cloud"
                                                  :alias-for "qwen3.6-35b-a3b"})))

(deftest an-inference-request-sends-the-alias
  (let [plan (cloud/plan-inference policy admitted-model {:messages [{:role "user" :content "hi"}]})]
    (is (cloud/allowed? plan))
    (is (= "https://api.murakumo.cloud/v1/messages" (get-in plan [:aiueos.cloud/request :url])))
    (is (= "murakumo-main" (get-in plan [:aiueos.cloud/request :body :model])))
    (is (false? (:aiueos.cloud/pinned? plan)))))

(deftest pinning-to-what-the-alias-currently-points-at-is-refused
  (let [plan (cloud/plan-inference policy admitted-model
                                   {:messages [{:role "user" :content "hi"}]
                                    :model-override "qwen3.6-35b-a3b"})]
    (is (= :model-is-alias-target (:aiueos.cloud/reason plan))
        "that override looks like precision and is a snapshot")))

(deftest a-deliberate-pin-to-another-model-is-honoured
  (let [plan (cloud/plan-inference policy admitted-model
                                   {:messages [{:role "user" :content "hi"}]
                                    :model-override "some-other-model"})]
    (is (cloud/allowed? plan))
    (is (= "some-other-model" (get-in plan [:aiueos.cloud/request :body :model])))
    (is (true? (:aiueos.cloud/pinned? plan))
        "the plan says it was pinned, so a receipt can too")))

(deftest a-request-with-no-messages-is-refused
  (is (= :messages-missing
         (:aiueos.cloud/reason (cloud/plan-inference policy admitted-model {:messages []})))))

;; ── performing ────────────────────────────────────────────────────────────

(deftest an-allowed-plan-reaches-the-fetch-function
  (let [plan (cloud/plan-block-read policy raw-cid)
        seen (atom nil)
        r (cloud/perform policy plan (fn [req] (reset! seen req) {:status 200}))]
    (is (:ok? r))
    (is (= :get (:method @seen)))
    (is (= (get-in plan [:aiueos.cloud/request :url]) (:url @seen)))))

(deftest a-denied-plan-never-reaches-the-fetch-function
  (let [plan (cloud/plan-block-read no-network raw-cid)
        called (atom false)
        r (cloud/perform no-network plan (fn [_] (reset! called true) {:status 200}))]
    (is (false? (:ok? r)))
    (is (= :origin-not-allowed (:aiueos.cloud/denied r)))
    (is (false? @called))))

(deftest a-plan-whose-url-stopped-being-allowed-is-checked-again-at-call-time
  (let [plan (cloud/plan-block-read policy raw-cid)
        called (atom false)
        r (cloud/perform no-network plan (fn [_] (reset! called true) {:status 200}))]
    (is (false? (:ok? r)))
    (is (false? @called)
        "planning-time approval is not a ticket the call site stops checking")))

;; ── every reason this namespace can produce is declared ───────────────────

(deftest the-declared-reason-set-is-complete
  (doseq [r [:cid-unparsable :cid-not-raw :origin-not-allowed :plan-not-allowed
             :insecure-transport :no-trust-anchors :peer-unmeasured :peer-not-pinned
             :response-not-ok :digest-missing :digest-mismatch
             :alias-unresolved :resolved-endpoint-not-allowed
             :model-is-alias-target :messages-missing]]
    (is (contains? cloud/deny-reasons r) (str r " is produced but not declared"))))
