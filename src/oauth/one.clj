(ns oauth.one
  "Provides functions for generating requests, and parsing responses necessary
  for integrating with three-legged OAuth 1.0 providers like Twitter.

  All Token requests and Protected Resources requests MUST be signed by the
  Consumer and verified by the Service Provider. The purpose of signing requests
  is to prevent unauthorized parties from using the Consumer Key and Tokens when
  making Token requests or Protected Resources requests. The signature process
  encodes the Consumer Secret and Token Secret into a verifiable value which is
  included with the request.

  OAuth does not mandate a particular signature method, as each implementation
  can have its own unique requirements. The protocol defines three signature
  methods: HMAC-SHA1, RSA-SHA1, and PLAINTEXT, but Service Providers are free to
  implement and document their own methods. Recommending any particular method
  is beyond the scope of this specification.

  The Consumer declares a signature method in the `oauth_signature_method`
  parameter, generates a signature, and stores it in the `oauth_signature`
  parameter. The Service Provider verifies the signature as specified in each
  method. When verifying a Consumer signature, the Service Provider SHOULD check
  the request nonce to ensure it has not been used in a previous Consumer
  request.

  The signature process MUST NOT change the request parameter names or values,
  with the exception of the `oauth_signature` parameter.

  For more information refer to the OAuth 1.0 specification at
  http://oauth.net/core/1.0/#signing_process."
  (:require [clojure.string :as str]
            [pandect.core :as pandect]
            [ring.util.codec :as codec]
            [schema.core :as s]))

;; -----------------------------------------------------------------------------
;; Schema

(def ^:private signature-algos
  "Mapping from keyword algorithm used in a consumer to the string version used
  in the OAuth Authorization header."
  {:hmac-sha1 "HMAC-SHA1"
   :plaintext "PLAINTEXT"
   :rsa-sha1 "RSA-SHA1"})

(def SignatureAlgo
  (apply s/enum (keys signature-algos)))

(def SignatureMethod
  (apply s/enum (vals signature-algos)))

(def ConsumerConfig
  {:access-uri s/Str
   :authorize-uri s/Str
   :callback-uri s/Str
   :key s/Str
   :request-uri s/Str
   :secret s/Str
   :signature-algo SignatureAlgo})

(def ^:private Map
  "Hash-map of keyword or string to any value"
  {(s/either s/Keyword s/Str) s/Any})

(def OAuthAuthorization
  "Valid attributes and corresponding values allowed in the unsigned OAuth
  Authorization header."
  {(s/optional-key "oauth_callback") s/Str
   (s/optional-key "oauth_token") s/Str
   (s/optional-key "oauth_verifier") s/Str
   (s/optional-key "oauth_version") s/Str
   (s/required-key "oauth_consumer_key") s/Str
   (s/required-key "oauth_nonce") s/Str
   (s/required-key "oauth_signature_method") SignatureMethod
   (s/required-key "oauth_timestamp") (s/either s/Str s/Int)})

(def SignedOAuthAuthorization
  "Signed version of the valid attributes and corresponding values allowed in
  the OAuth Authorization header. See `OAuthAuthorization`."
  (assoc OAuthAuthorization (s/required-key "oauth_signature") s/Str))

(def ^:private RequestTokenParams
  {(s/optional-key "oauth_callback") s/Str})

(def ^:private AuthorizationParams
  (assoc Map (s/optional-key :callback-uri) s/Str
         (s/optional-key "oauth_token") s/Str))

(def ^:private RequestMethod
  "Valid HTTP request methods"
  (s/enum :delete :get :head :patch :post :put :trace))

(def ^:private Request
  "A clj-http compatible request map that is also OAuth 1.0 compatible."
  {(s/optional-key :form-params) Map
   (s/optional-key :headers) {s/Str s/Str}
   (s/optional-key :query-params) Map
   :request-method RequestMethod
   :url s/Str})

(def ^:private OAuthRequest
  "clj-http compatible request map with required `:oauth-headers` that will be
  used to generate a signature."
  (assoc Request (s/optional-key :oauth-headers) OAuthAuthorization))

(def ^:private SignedRequest
  "Signed OAuth request with an Authorization header."
  (assoc Request
         (s/optional-key :headers)
         {(s/required-key "Authorization") s/Str
          s/Str s/Str}))

(def ^:private AccessToken
  {(s/optional-key :token) (s/maybe s/Str)
   (s/optional-key :secret) (s/maybe s/Str)})

(def ^:private AccessTokenArg
  (s/conditional
   map? AccessToken
   :else s/Str))

;; -----------------------------------------------------------------------------
;; Utils

(defn- filter-vals
  [m]
  (into (empty m) (filter val m)))

(s/defn ^:private split-url :- [(s/one s/Str "base-url") (s/maybe {s/Str s/Str})]
  [url]
  (let [uri (java.net.URI. url)]
    [(str (.getScheme uri) "://" (.getAuthority uri) (.getPath uri))
     (some-> uri .getQuery codec/form-decode)]))

;; -----------------------------------------------------------------------------
;; OAuth encoded

(s/defn oauth-encode :- s/Str
  "Encode string according to RFC 3986."
  [s]
  (-> (str s)
      (java.net.URLEncoder/encode "UTF-8")
      (.replace "+" "%20")
      (.replace "*" "%2A")
      (.replace "%7E" "~")))

(s/defn oauth-decode :- s/Str
  "Decode an RFC 3986 encoded string."
  [^String s]
  (java.net.URLDecoder/decode s "UTF-8"))

;; -----------------------------------------------------------------------------
;; Nonce

(def ^:private ^java.util.Random secure-random
  (java.security.SecureRandom/getInstance "SHA1PRNG"))

(def ^:private nonce-chars
  (mapv #(Character/toString (char %))
        (concat (range 48 57) (range 65 90) (range 97 122))))

(s/defn nonce :- s/Str
  [length :- s/Int]
  (let [n (count nonce-chars)]
    (str/join (repeatedly length #(nth nonce-chars (.nextInt secure-random n))))))

;; -----------------------------------------------------------------------------
;; Consumer

(defrecord Consumer
    [access-uri authorize-uri callback-uri key secret signature-algo])

(s/defn make-consumer :- Consumer
  "Create a new consumer instance with necessary URIs, key and secret."
  [config :- ConsumerConfig]
  (map->Consumer config))

;; -----------------------------------------------------------------------------
;; Request signing

(s/defn parse-auth-header :- {s/Str s/Str}
  "The inverse of `auth-headers->str`."
  [s :- s/Str]
  (reduce
   #(if-let [[_ k v] (re-find #"(.*?)=\"(.*?)\"" %2)]
      (assoc %1 k (codec/url-decode v))
      %1)
   {}
   (str/split (str/replace s #"(?i)^oauth\s+" "") #",\s+")))

(s/defn auth-headers->str :- s/Str
  "The OAuth Protocol Parameters are sent in the Authorization header the
  following way:

  1. Parameter names and values are encoded per Parameter Encoding.
  2. For each parameter, the name is immediately followed by an ‘=’ character
     (ASCII code 61), a ‘”’ character (ASCII code 34), the parameter value (MAY
     be empty), and another ‘”’ character (ASCII code 34).
  3. Parameters are separated by a comma character (ASCII code 44) and OPTIONAL
     linear whitespace per [RFC2617](http://oauth.net/core/1.0/#RFC2617).
  4. The OPTIONAL realm parameter is added and interpreted per
     [RFC2617](http://oauth.net/core/1.0/#RFC2617), section 1.2.

  http://oauth.net/core/1.0/#auth_header"
  [m :- {s/Str s/Any}]
  (->> m
       (map #(format "%s=\"%s\""
                     (key %)
                     (-> % val oauth-encode)))
       (str/join ", ")))

(s/defn ->seconds :- s/Int
  [millis :- s/Int]
  (quot ^int millis 1000))

(s/defn sign :- s/Str
  [consumer :- Consumer oauth-token-secret :- (s/maybe s/Str) data :- s/Str]
  (let [{:keys [secret signature-algo]} consumer]
    (case signature-algo
      :hmac-sha1
      (codec/base64-encode
       (pandect/sha1-hmac-bytes
        data
        (format "%s&%s"
                (oauth-encode secret)
                (oauth-encode (or oauth-token-secret ""))))))))

(s/defn ^:private base-string :- s/Str
  "http://oauth.net/core/1.0/#anchor14

  The Signature Base String is a consistent reproducible concatenation of the
  request elements into a single string. The string is used as an input in
  hashing or signing algorithms. The HMAC-SHA1 signature method provides both a
  standard and an example of using the Signature Base String with a signing
  algorithm to generate signatures. All the request parameters MUST be encoded
  as described in Parameter Encoding prior to constructing the Signature Base
  String.

  The following items MUST be concatenated in order into a single string. Each
  item is encoded and separated by an ‘&’ character (ASCII code 38), even if
  empty.

  1. The HTTP request method used to send the request. Value MUST be uppercase,
     for example: `HEAD`, `GET`, `POST`, etc.
  2. The request URL from Section 9.1.2.
  3. The normalized request parameters string from Section 9.1.1."
  [method :- (s/either s/Keyword s/Str)
   uri :- s/Str
   params :- Map]
  {:pre [(sorted? params)]}
  (format "%s&%s&%s"
          (-> method name str/upper-case)
          (oauth-encode uri)
          (->> params
               filter-vals
               (map (fn [[k v]]
                      (format "%s=%s" k (oauth-encode (str v)))))
               (str/join "&")
               oauth-encode)))

(s/defn make-oauth-headers :- OAuthAuthorization
  [consumer :- Consumer]
  (sorted-map
   "oauth_consumer_key"     (:key consumer)
   "oauth_nonce"            (nonce 32)
   "oauth_signature_method" (-> consumer :signature-algo signature-algos)
   "oauth_timestamp"        (->seconds (System/currentTimeMillis))
   "oauth_version"          "1.0"))

(s/defn ^:private sign-request-impl :- SignedRequest
  ([consumer oauth-request] (sign-request-impl consumer oauth-request {}))
  ([consumer :- Consumer
    oauth-request :- OAuthRequest
    access-token :- AccessToken]
   (let [{:keys [form-params
                 oauth-headers
                 query-params
                 request-method
                 url]} oauth-request
         {access-token-secret :secret} access-token
         [base-url url-query-params] (split-url url)
         params (merge oauth-headers url-query-params query-params form-params)
         base-string (base-string request-method base-url params)
         signed-params (assoc oauth-headers
                              "oauth_signature"
                              (sign consumer access-token-secret base-string))]
     (with-meta
       (-> oauth-request
           (dissoc :oauth-headers)
           (assoc-in [:headers "Content-Type"]
                     "application/x-www-form-urlencoded")
           (assoc-in [:headers "Authorization"]
                     (str "OAuth " (auth-headers->str signed-params))))
       {:base-url base-url
        :query-params query-params
        :base-string base-string
        :signed-params signed-params}))))

(s/defn ^:private normalize-access-token-arg :- AccessToken
  [x :- (s/maybe AccessTokenArg)]
  (cond
    (and (map? x) (contains? x :token) (contains? x :secret)) x
    (string? x) {:secret x}
    (nil? x) {}
    :else (throw (IllegalArgumentException.
                  (str "access-token passed to `sign-request` must be a map of "
                       "`:token` and `:secret`, or "
                       "an access token secret as a string.")))))

(s/defn sign-request :- SignedRequest
  ([consumer oauth-request]
   (sign-request consumer oauth-request nil))
  ([consumer :- Consumer
    {:keys [oauth-headers] :as oauth-request} :- OAuthRequest
    access-token-arg :- (s/maybe AccessTokenArg)]
   (let [;; In order to support both the string and map version of the
         ;; `access-token` we need to normalise the input into the preferred map
         ;; form.
         ;;
         ;; If the token is something other than a valid map or string we throw
         ;; an `IllegalArgumentException`.
         {:keys [token]
          :as access-token} (normalize-access-token-arg access-token-arg)
         ;; To allow optional `oauth-headers` from users calling this function
         ;; directly we conditionally use a new map of sorted OAuth headers.
         ;;
         ;; When we've got an OAuth token to sign the request with, we add that
         ;; to the OAuth headers for use in `sign-request-impl`.
         oauth-headers (cond-> (or oauth-headers (make-oauth-headers consumer))
                         (some? token) (assoc "oauth_token" token))]
     (sign-request-impl consumer
                        (assoc oauth-request :oauth-headers oauth-headers)
                        access-token))))

;; -----------------------------------------------------------------------------
;; Request token

(s/defn request-token-request
  "Generate a clj-http compatible request map that will request a token from the
  provider associated with `consumer`.

  http://oauth.net/core/1.0/#auth_step1

  The Consumer obtains an unauthorized Request Token by asking the Service
  Provider to issue a Token. The Request Token’s sole purpose is to receive
  User approval and can only be used to obtain an Access Token.

  To obtain a Request Token, the Consumer sends an HTTP request to the Service
  Provider’s Request Token URL. The Service Provider documentation specifies
  the HTTP method for this request, and HTTP POST is RECOMMENDED.

  Note, if you override the \"oauth_callback\" via `params`, you need to pass
  the same callback URI to `authorization-url`."
  ([consumer :- Consumer] (request-token-request consumer {}))
  ([consumer :- Consumer params :- RequestTokenParams]
   (sign-request-impl
    consumer
    {:oauth-headers
     (assoc
      (make-oauth-headers consumer)
      "oauth_callback" (get params "oauth_callback" (:callback-uri consumer)))
     :request-method :post
     :url (:request-uri consumer)})))

;; -----------------------------------------------------------------------------
;; User authorisation

(s/defn authorization-url
  "Generate a provider-specific authorisation URL that you send the user's agent
  (aka. browser) to typically via an HTTP redirect.

  Optional `params` can be passed to append to the authorisation URL via a query
  string.

  `params` may contain an \"oauth_callback\" to override any callback URI in the
  consumer. This can be useful when you need to pass some state for CSRF
  protection to the OAuth provider.

  Note, if you override the \"oauth_callback\" via `params`, you need to pass
  the same callback URI to `request-token-request`."
  ([consumer :- Consumer] (authorization-url consumer {}))
  ([consumer :- Consumer params :- AuthorizationParams]
   (format
    "%s?%s"
    (:authorize-uri consumer)
    (-> {"oauth_callback" (:callback-uri consumer)}
        (merge params)
        filter-vals
        codec/form-encode))))

;; -----------------------------------------------------------------------------
;; Access token request

(s/defn ^:always-validate access-token-request
  "Generate a signed request that will ask the OAuth provider for an access
  token.

  This request must contain the token and verifier provided by the OAuth
  provider when they redirect back to your application after you send someone to
  the authorisation URL generated by `authorization-url`."
  [consumer :- Consumer
   creds :- {(s/optional-key "oauth_token") s/Str
             (s/optional-key "oauth_verifier") s/Str}]
  (sign-request-impl
   consumer
   {:oauth-headers
    (merge
     (make-oauth-headers consumer)
     (when-let [token (get creds "oauth_token")]
       {"oauth_token" token})
     (when-let [verifier (get creds "oauth_verifier")]
       {"oauth_verifier" verifier}))
    :request-method :post
    :url (:access-uri consumer)}))
