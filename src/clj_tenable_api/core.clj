;; Filename: core.clj
;; Description: Basic Tenable.io and Tenable.SC API functionality.
;; Created by: Benjamin M. Singleton
;; Date: 2021/07/20
(ns clj-tenable-api.core
  (:require [clj-http.client :as client]
            [clojure.data.json :as clj-json]
            [cheshire.core :as json]
            [cheshire.parse :as parse]))

(defn get-users-list
  "Get the list of users in Tenable.io."
  [access-key secret-key]
  (client/get "https://cloud.tenable.com/users"
    {:headers {"Accept" "application/json",
    "X-ApiKeys" (str "accessKey=" access-key ";secretKey=" secret-key)}}))

(defn tenable-sc-list-users
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

(defn tenable-sc-launch-scan
  "Launches a scan with a given Active Scan ID, returning the Scan
  Result ID of the resulting scan instance."
  [access-key secret-key scan-id]
  (get-in
    (client/post
      (str "https://192.168.50.201/rest/scan/" scan-id "/launch")
        {:insecure? true
          :as :json
          :headers {"Accept" "application/json", "x-apikey"
            (str "accessKey=" access-key ";secretKey=" secret-key)}})
    [:body :response :scanResult :id]))

(defn generate-active-scan-body
  "Generates the payload for a Tenable.SC Active Scan based on a given
  policy ID and a list of target IPs."
  ([scan-name policy-id ip-list]
    {:name scan-name
      :ipList ip-list
      :repository {:id 1}
      :policy {:id policy-id}
      :type "policy"
      })
  ([]
    (generate-active-scan-body "Test scan" "1000003" "192.168.8.161")))

(defn stringify-tenable-payload
  "OBSOLETE:
  Casts a Clojure map (possibly containing maps and vectors) as a
  string, converting the key values to json-like keys and inserting
  commas between consecutive maps."
  [body]
  (clojure.string/replace
    (clojure.string/replace (str body) #"\:(\S+)" "\"$1\":")
    #"\}\s\{" "}, {"))

(defn tenable-sc-create-scan
  "Creates a new Active Scan in Tenable.SC, using the
  generate-active-scan-body function."
  [access-key secret-key]
  (get-in
    (client/post
      "https://192.168.50.201/rest/scan"
        {:insecure? true
          :as :json
          :headers {"Accept" "application/json", "x-apikey"
            (str "accessKey=" access-key ";secretKey=" secret-key)}
          :body (clj-json/write-str (generate-active-scan-body))
            })
    [:body :response :id]))

(defn generate-analysis-query
  "Generates a Tenable.SC Vulnerability Analysis query, filtering on
  hostname and plugin ID, specifically using the
  'Vulnerability Detail List' view."
  [hostname plugin_id]
  {
    :type "vuln"
    :sourceType "cumulative"
    :query {
      :startOffset "0"
      :endOffset "50"
      :type "vuln"
      :vulnTool "vulndetails"
      :tool "vulndetails"
  :filters [
    {
      :id "ip", :filterName "ip", :operator "=",
      :type "vuln" :isPredefined "true",
      :value hostname
    },
    {
      :id "pluginID", :filterName "pluginID", :operator "=",
      :type "vuln", :isPredefined "true", :value plugin_id}]}})

(defn tenable-sc-vuln-analysis
  "Runs a vulnerability analysis query based on hostname and plugin ID.
  This query is generated through the generate-analysis-query function,
  which specifically uses the 'Vulnerability Detail List' view."
  [access-key secret-key hostname plugin_id]
  (get-in
    (client/post
      "https://192.168.50.201/rest/analysis"
        {:insecure? true
          :as :json
          :headers {"Accept" "application/json", "x-apikey"
            (str "accessKey=" access-key ";secretKey=" secret-key)}
          :body (clj-json/write-str (generate-analysis-query hostname plugin_id))
            })
    [:body]))

;; (client/put "http://example.com/api" {:body "my PUT body"})

(defn -main
  "Make a simple http request."
  [& args]
  (let [keys (clojure.string/split-lines
    (slurp "src/clj_tenable_api/tenable_sc_keys.txt"))]
    (println
      (map-usernames-to-ids
        (tenable-sc-list-users (nth keys 0) (nth keys 1))))
    (let [new-scan (tenable-sc-create-scan (nth keys 0) (nth keys 1))]
      (println (str "Creating scan with Active Scan ID " new-scan))
      (println (str "Launching scan with scan result ID "
        (tenable-sc-launch-scan (nth keys 0) (nth keys 1) new-scan))))
    (println (str "Querying plugin 19506 on host 192.168.8.161 "
      (tenable-sc-vuln-analysis (nth keys 0) (nth keys 1) "192.168.8.161" "19506")))
    ))
