(ns grant.device-attest-test
  "The signing input is a wire rule, so what it produces is pinned as a
  literal rather than recomputed from the same expression under test -- a test
  that rebuilds the string with the same `str` call would agree with any
  framing, including a broken one.

  Every refusal names its own reason, so a check that stops discriminating
  cannot pass by refusing for a different cause."
  (:require [grant.device-attest :as da]
            [kotoba.lang.text :as text]
            [clojure.test :refer [deftest is testing]]))

(def fields
  {:did "did:key:z6MkfakeDevice"
   :endpoint "https://murakumo.cloud"
   :nonce "n0nce-abc"})

(deftest the-signed-string-is-pinned
  (is (= "aiueos-device-attest-v1\ndid:key:z6MkfakeDevice\nhttps://murakumo.cloud\nn0nce-abc\n"
         (da/signing-input fields))
      "the exact bytes both sides sign; changing this invalidates every signature")
  (testing "the domain separator is part of it"
    (is (text/starts-with? (da/signing-input fields)
                                     "aiueos-device-attest-v1\n")))
  (testing "every field is terminated, so there is no trailing-empty question"
    (is (text/ends-with? (da/signing-input fields) "\n"))))

(deftest different-tuples-cannot-collide
  ;; The property the framing exists for: no two distinct (did, endpoint,
  ;; nonce) triples produce the same bytes.
  (let [a (da/signing-input fields)
        b (da/signing-input (assoc fields :did "did:key:z6MkotherDevice"))
        c (da/signing-input (assoc fields :endpoint "https://evil.example"))
        d (da/signing-input (assoc fields :nonce "n0nce-abd"))]
    (is (= 4 (count (distinct [a b c d]))))))

(deftest a-field-that-could-forge-the-framing-is-refused
  ;; Without this, "a\nb" as an endpoint would frame itself as two fields and
  ;; let a different triple produce identical bytes.
  (is (= :field-contains-separator
         (:error (da/signing-input (assoc fields :endpoint "https://a\nhttps://b")))))
  (is (= :field-contains-separator
         (:error (da/signing-input (assoc fields :nonce "x\ny")))))
  (testing "and the other ways the fields can be unusable are named apart"
    (is (= :field-blank (:error (da/signing-input (assoc fields :nonce "")))))
    (is (= :field-blank (:error (da/signing-input (assoc fields :did "   ")))))
    (is (= :field-not-a-string (:error (da/signing-input (dissoc fields :did)))))
    (is (= :field-not-a-string (:error (da/signing-input (assoc fields :nonce 42)))))))

;; ── polling ───────────────────────────────────────────────────────────────

(deftest a-pending-challenge-is-signed
  (let [p (da/plan-poll {:status 200
                         :body {"challenge" "c1" "nonce" "n1" "expiresAtMs" 9000}
                         :now-ms 1000})]
    (is (= :sign (:action p)))
    (is (= "c1" (:challenge p)))
    (is (= "n1" (:nonce p)))))

(deftest nothing-to-do-and-cannot-ask-are-different-answers
  ;; The load-bearing distinction. An agent that cannot reach its control
  ;; plane must not report what an agent that reached it and was told there is
  ;; nothing pending reports.
  (let [idle (da/plan-poll {:status 404 :body {"challenge" nil} :now-ms 1000})
        down (da/plan-poll {:status nil :body nil :now-ms 1000})]
    (is (= :idle (:action idle)))
    (is (= :no-challenge-pending (:reason idle)))
    (is (= :refuse (:action down)))
    (is (= :control-plane-unreachable (:reason down)))
    (is (not= (:action idle) (:action down)))
    (is (not= (da/exit-codes :idle) (da/exit-codes :unreachable))
        "and they exit differently, so a supervisor can tell them apart")))

(deftest a-dead-challenge-is-skipped-not-signed
  (let [p (da/plan-poll {:status 200
                         :body {"challenge" "c1" "nonce" "n1" "expiresAtMs" 1000}
                         :now-ms 1000})]
    (is (= :skip (:action p)))
    (is (= :challenge-expired (:reason p)))))

(deftest malformed-answers-are-refused-by-name
  (doseq [[expected in]
          [[:malformed-challenge {:status 200 :body {"challenge" "c" "nonce" "" "expiresAtMs" 9000}}]
           [:malformed-challenge {:status 200 :body {"challenge" nil "nonce" "n" "expiresAtMs" 9000}}]
           [:missing-expiry      {:status 200 :body {"challenge" "c" "nonce" "n"}}]
           [:unexpected-not-found {:status 404 :body {"error" "gone"}}]
           [:unexpected-status   {:status 500 :body {}}]]]
    (let [p (da/plan-poll (assoc in :now-ms 1000))]
      (is (= :refuse (:action p)))
      (is (= expected (:reason p)) (str "for " (pr-str in))))))

;; ── attesting ─────────────────────────────────────────────────────────────

(deftest the-outcomes-of-attesting-are-distinct
  (is (= :proved (:outcome (da/interpret-attest {:status 200 :body {"verified" true}}))))
  (testing "a 200 that does not say true is not a proof"
    (is (= :rejected (:outcome (da/interpret-attest {:status 200 :body {"verified" false}}))))
    (is (= :verified-not-true (:reason (da/interpret-attest {:status 200 :body {}})))))
  (is (= :rejected (:outcome (da/interpret-attest {:status 400 :body {"verified" false}}))))
  (is (= :no-challenge (:outcome (da/interpret-attest {:status 404 :body {}}))))
  (is (= :gone (:outcome (da/interpret-attest {:status 410 :body {}}))))
  (is (= :unreachable (:outcome (da/interpret-attest {:status nil :body nil}))))
  (is (= :error (:outcome (da/interpret-attest {:status 503 :body {}})))))

(deftest a-refused-signature-is-not-a-transport-problem
  ;; :rejected means the plane read a signature this device made and did not
  ;; accept it. Retrying does not fix that, and its exit code says so.
  (is (not= (da/exit-codes :rejected) (da/exit-codes :unreachable)))
  (is (pos? (da/exit-codes :rejected)))
  (is (zero? (da/exit-codes :proved)))
  (is (zero? (da/exit-codes :idle))))
