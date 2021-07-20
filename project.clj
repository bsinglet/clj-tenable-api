(defproject clj-tenable-api "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.clojure/tools.reader "1.3.6"]
                 [clj-http "3.12.3"]
                 [cheshire "5.10.0"]]
  :main ^:skip-aot clj-tenable-api.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
