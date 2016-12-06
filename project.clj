(defproject oauth/oauth.one "0.7.0-SNAPSHOT"
  :description "OAuth 1.0 in Clojure"
  :url "https://github.com/jcf/oauth-one"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.bouncycastle/bcprov-jdk15on "1.55"]
                 [org.clojure/clojure "1.8.0"]
                 [pandect "0.6.1"]
                 [prismatic/schema "1.1.3"]
                 [ring/ring-codec "1.0.1"]]
  :profiles
  {:dev {:dependencies [[org.clojure/test.check "0.9.0"]]}})
