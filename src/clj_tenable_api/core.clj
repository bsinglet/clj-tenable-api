(ns clj-tenable-api.core
  (:require [clj-http.client :as client]
            [cheshire.core :as json]
            [cheshire.parse :as parse]))

(defn get-users-list
  "Get the list of users in Tenable.io."
  [access-key secret-key]
  (client/get "https://cloud.tenable.com/users"
    {:headers {"Accept" "application/json",
    "X-ApiKeys" (str "accessKey=" access-key ";secretKey=" secret-key)}}))

(defn tenable-sc-ignore-certs
  "Example call to a local Tenable.SC server, ignoring the fact that
  it's using self-signed certs."
  [access-key secret-key]
  (client/get "https://192.168.50.201/rest/user?fields=apiKeys%2Cname%2Cusername%2Cfirstname%2Clastname%2Cgroup%2Crole%2ClastLogin%2CcanManage%2CcanUse%2Clocked%2Cstatus%2Ctitle%2Cemail%2Cid%2CauthType" {:insecure? true
    :headers {"Accept" "application/json",
    "x-apikey" (str "accessKey=" access-key ";secretKey=" secret-key)}}))

;; (client/put "http://example.com/api" {:body "my PUT body"})

;; (client/post "http://example.com/api"
;;             {:basic-auth ["user" "pass"]
;;              :body "{\"json\": \"input\"}"
;;              :headers {"X-Api-Version" "2"}
;;              :content-type :json
;;              :socket-timeout 1000      ;; in milliseconds
;;              :connection-timeout 1000  ;; in milliseconds
;;              :accept :json})

(defn -main
  "Make a simple http request."
  [& args]
  (println (get-users-list "" ""))
  (println (tenable-sc-ignore-certs "" "")))
