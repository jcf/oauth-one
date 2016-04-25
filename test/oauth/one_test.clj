(ns oauth.one-test
  (:require [clojure.test :refer :all]
            [clojure.test.check
             [clojure-test :refer [defspec]]
             [generators :as gen]
             [properties :as prop]]
            [oauth.one :refer :all]
            [ring.util.codec :as codec]
            [schema
             [core :as s]
             [test :refer [validate-schemas]]]))

(use-fixtures :once validate-schemas)

;; -----------------------------------------------------------------------------
;; Schema

(def ^:private urlencoded
  "application/x-www-form-urlencoded")

(def ^:private SignedRequest
  {:headers {(s/required-key "Authorization") s/Str
             (s/required-key "Content-Type") (s/eq urlencoded)
             s/Str s/Str}
   :request-method (s/eq :post)
   :url s/Str})

;; -----------------------------------------------------------------------------
;; Utils

(def ^:private consumer-config
  {:access-uri "http://example.com/access"
   :authorize-uri "http://example.com/authorize"
   :callback-uri "http://localhost/oauth/callback"
   :key "key"
   :request-uri "http://example.com/token"
   :secret "secret"
   :signature-algo :hmac-sha1})

(defn- request->auth
  [request]
  (-> request
      (get-in [:headers "Authorization"])
      parse-auth-header))

(defn- parse-uri
  [^String url]
  (let [uri (java.net.URI. url)]
    {:authority (.getAuthority uri)
     :host (.getHost uri)
     :path (.getPath uri)
     :query (.getQuery uri)
     :scheme (.getScheme uri)}))

(defn- split-url
  [^String url]
  (let [{:keys [scheme host path query]} (parse-uri url)]
    [(str scheme "://" host path) (codec/form-decode query)]))

;; -----------------------------------------------------------------------------
;; Consumer

(deftest t-make-consumer
  (is (make-consumer consumer-config)))

;; -----------------------------------------------------------------------------
;; Auth headers

(deftest t-parse-auth-header
  (are [s m] (= (parse-auth-header s) m)
    "" {}

    "oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\""
    {"oauth_callback" "http://example.com/callback"}

    (str "oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\", "
         "oauth_nonce=\"abc123\"")
    {"oauth_callback" "http://example.com/callback"
     "oauth_nonce" "abc123"}))

(defspec t-auth-headers-roundtrip
  (prop/for-all [m (gen/map gen/string-alphanumeric gen/string-alphanumeric)]
    (= m (parse-auth-header (format "OAuth %s" (auth-headers->str m))))))

(deftest t-auth-headers->str
  (are [m s] (= (auth-headers->str m) s)
    {} ""

    {"oauth_callback" "http://example.com/callback"}
    "oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\""

    {"oauth_callback" "http://example.com/callback"
     "oauth_nonce" "abc123"}
    (str "oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\", "
         "oauth_nonce=\"abc123\"")))

;; -----------------------------------------------------------------------------
;; Request tokens

(deftest t-request-token-request
  (let [consumer (make-consumer consumer-config)
        request (request-token-request consumer)
        auth (request->auth request)]
    (is (nil? (s/check SignedRequest request)))
    (is (= "http://example.com/token" (:url request)))
    (is (nil? (s/check SignedOAuthAuthorization auth)))
    (are [k v] (= (get auth k ::missing) v)
      "oauth_callback" "http://localhost/oauth/callback"
      "oauth_consumer_key" "key"
      "oauth_signature_method" "HMAC-SHA1")))

(deftest t-request-token-request-with-callback-override
  (let [consumer (make-consumer consumer-config)
        request (request-token-request
                 consumer {"oauth_callback" "http://localhost/override"})
        auth (request->auth request)]
    (is (nil? (s/check SignedRequest request)))
    (is (= "http://example.com/token" (:url request)))
    (is (nil? (s/check SignedOAuthAuthorization auth)))
    (are [k v] (= (get auth k ::missing) v)
      "oauth_callback" "http://localhost/override"
      "oauth_consumer_key" "key"
      "oauth_signature_method" "HMAC-SHA1")))

;; -----------------------------------------------------------------------------
;; Authorisation URL

(deftest t-authorization-url
  (let [consumer (make-consumer consumer-config)]
    (is (= ["http://example.com/authorize"
            {"oauth_callback" "http://localhost/oauth/callback"}]
           (split-url (authorization-url consumer))))
    (is (= ["http://example.com/authorize"
            {"a" "1" "b" "2"
             "oauth_callback" "http://localhost/oauth/callback"
             "oauth_token" "token"}]
           (split-url (authorization-url
                       consumer {"oauth_token" "token" :a 1 :b 2}))))
    (is (= ["http://example.com/authorize"
            {"a" "1" "b" "2"
             "oauth_callback" "http://localhost/override"
             "oauth_token" "token"}]
           (-> consumer
               (authorization-url {"oauth_token" "token"
                                   "oauth_callback" "http://localhost/override"
                                   :a 1
                                   :b 2})
               split-url)))))

;; -----------------------------------------------------------------------------
;; Access token request

(deftest t-access-token-request
  (let [consumer (make-consumer consumer-config)
        request (access-token-request consumer {"oauth_token" "token"
                                                "oauth_verifier" "verifier"})
        auth (request->auth request)]
    (is (nil? (s/check SignedRequest request)))
    (is (= "http://example.com/access" (:url request)))
    (is (nil? (s/check SignedOAuthAuthorization auth)))
    (are [k v] (= (get auth k ::missing) v)
      "oauth_consumer_key" "key"
      "oauth_signature_method" "HMAC-SHA1"
      "oauth_token" "token"
      "oauth_verifier" "verifier")))

;; -----------------------------------------------------------------------------
;; Signature generation

(def ^:private test-requests
  [
   {:desc "With no OAuth headers"
    :in
    {:url "https://example.com/"
     :request-method :post}}

   {:desc "With just OAuth headers"
    :in
    {:oauth-headers {"oauth_consumer_key" "abc123"
                     "oauth_nonce" "nonce"
                     "oauth_signature_method" "HMAC-SHA1"
                     "oauth_timestamp" "1000"
                     "oauth_version" "1.0"}
     :request-method :post
     :url "https://example.com/"}
    :signature "yEzHR87PoGcUSua/F+48V/Nzd3M="}

   {:desc "With OAuth headers and form params"
    :in
    {:form-params {"status" "testing things!"}
     :oauth-headers {"oauth_consumer_key" "abc123"
                     "oauth_nonce" "nonce"
                     "oauth_signature_method" "HMAC-SHA1"
                     "oauth_timestamp" "1000"
                     "oauth_version" "1.0"}
     :request-method :post
     :url "https://example.com/"}
    :signature "8ZoF1R8s/7JRKivUJkPs/1yhaZU="}])

(deftest t-sign-request
  (let [consumer (make-consumer consumer-config)]
    (doseq [{:keys [signature in]} test-requests
            :let [request (sign-request consumer in)
                  auth (request->auth request)]]
      (is (nil? (s/check SignedOAuthAuthorization auth)))
      (when signature
        (is (= signature (get auth "oauth_signature" ::missing)))))))
