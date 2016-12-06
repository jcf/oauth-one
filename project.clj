(defproject oauth/oauth.one "0.6.0"
  :description "OAuth 1.0 in Clojure"
  :url "https://github.com/jcf/oauth-one"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [pandect "0.5.4"]
                 [prismatic/schema "1.1.0"]
                 [ring/ring-codec "1.0.0"]]
  :profiles
  {:dev {:dependencies [[org.clojure/test.check "0.9.0"]]}})
