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
  it's using self-signed certs. This example lists out the users on
  the server."
  [access-key secret-key]
  (get-in
    (client/get "https://192.168.50.201/rest/user?fields=apiKeys%2Cname%2Cusername%2Cfirstname%2Clastname%2Cgroup%2Crole%2ClastLogin%2CcanManage%2CcanUse%2Clocked%2Cstatus%2Ctitle%2Cemail%2Cid%2CauthType" {:insecure? true
    :as :json
    :headers {"Accept" "application/json",
    "x-apikey" (str "accessKey=" access-key ";secretKey=" secret-key)}})
    [:body :response]))

  (defn map-usernames-to-ids
    "Takes a vector of hash-maps. Each map has the data for a Tenable.SC
    user. These maps have a lot of extraneous keys, so this function drops
    everything except the username and id."
    [users]
    (map #(hash-map :username (:username %), :id (:id %)) users))

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
  println
    (map-usernames-to-ids
      (tenable-sc-ignore-certs "" "")))
