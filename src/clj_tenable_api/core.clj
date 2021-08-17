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
  ([scan-name policy-id ip-list credential-id]
    {:name scan-name
      :ipList ip-list
      :repository {:id 1}
      :policy {:id policy-id}
      :type "policy"
      :credentials [{:id credential-id}]
      })
  ([]
    (generate-active-scan-body "Test scan" "1000003" "192.168.8.161" "1000003")))

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
  ([access-key secret-key]
    (tenable-sc-create-scan access-key secret-key "Test scan" "1000003" "192.168.8.161" "1000003"))
  ([access-key secret-key scan-name policy-id ip-list credential-id]
  (get-in
    (client/post
      "https://192.168.50.201/rest/scan"
        {:insecure? true
          :as :json
          :headers {"Accept" "application/json", "x-apikey"
            (str "accessKey=" access-key ";secretKey=" secret-key)}
          :body (clj-json/write-str (generate-active-scan-body scan-name policy-id ip-list credential-id))
            })
    [:body :response :id])))

(defn generate-credential-object-windows
  "Creates the payload for a Tenable.SC Windows credential object, using basic
  password authentication."
  [credential-name username password domain]
  {
    :name credential-name
    :authType "password"
    :type "windows"
    :username username
    :password password
    :domain domain  ; this field is optional, use "" to leave it out.
  })

(defn generate-credential-object-ssh
  "Creates the payload for a Tenable.SC SSH credential object, using sudo as
  the escalation method."
  [credential-name username password]
  {
    :name credential-name
    :authType "password"
    :type "ssh"
    :username username
    :password password
    :privilegeEscalation "sudo"
    :escalationUsername ""  ; leave blank to sudo as root
    :escalationPassword password  ; generally, the sudo password should be the escalating user's password
    :escalationPath ""  ; leave as blank to let Nessus use common locations for sudo
  })

(defn generate-credential-object-oracle
  "Creates the payload for a Tenable.SC Oracle db credential object."
  [credential-name username password sid]
  {
    :name credential-name
    :authType "password"
    :dbType "Oracle"
    :type "database"
    :oracleAuthType "NORMAL"
    :oracle_service_type "SID"
    :port "1521"
    :source "entry"
    :login username
    :password password
  })

(defn tenable-sc-create-credential
  "Creates a Tenable.SC credential object, has to be supplied the results from
  one of the generate-credential-object-* functions."
  [access-key secret-key payload]
  (get-in
    (client/post
      "https://192.168.50.201/rest/credential"
        {:insecure? true
          :as :json
          :headers {"Accept" "application/json", "x-apikey"
            (str "accessKey=" access-key ";secretKey=" secret-key)}
          :body (clj-json/write-str payload)
            })
    [:body :response :id]))

(defn generate-advanced-scan-policy
  "Specifies the essential fields for an Advanced Network Scan policy, with an
  audit file, too."
  [policy-name audit-file-id]
  {:name policy-name
   :auditFiles [{:id audit-file-id}]
   :policyTemplate {:id "1"}
   :preferences [
     :thorough_tests "no"
   ]
 })

(defn tenable-sc-create-policy
  "Creates an Advanced Network Scan policy with the given audit file attached."
  [access-key secret-key policy-name audit-file-id]
  (get-in
    (client/post
      "https://192.168.50.201/rest/policy"
        {:insecure? true
          :as :json
          :headers {"Accept" "application/json", "x-apikey"
            (str "accessKey=" access-key ";secretKey=" secret-key)}
          :body (clj-json/write-str
            (generate-advanced-scan-policy policy-name audit-file-id))
            })
    [:body :response :id]))

(defn tenable-sc-delete-credential
  "Deletes the given Tenable.SC credential object."
  [access-key secret-key credential-id]
  (get-in
    (client/delete
      (str "https://192.168.50.201/rest/credential/" credential-id)
      {:insecure? true
       :as :json
       :headers {"Accept" "application/json", "x-apikey"
         (str "accessKey=" access-key ";secretKey=" secret-key)}
        })
    [:body :response :id]))

(defn tenable-sc-delete-scan-policy
  "Deletes the given scan policy."
  [access-key secret-key policy-id]
  (get-in
    (client/delete
      (str "https://192.168.50.201/rest/policy/" policy-id)
      {:insecure? true
       :as :json
       :headers {"Accept" "application/json", "x-apikey"
         (str "accessKey=" access-key ";secretKey=" secret-key)}
        })
    [:body :response :id]))

(defn tenable-sc-delete-active-scan
  "Deletes the given active scan (but not its results.)"
  [access-key secret-key active-scan-id]
  (get-in
    (client/delete
      (str "https://192.168.50.201/rest/scan/" active-scan-id)
      {:insecure? true
       :as :json
       :headers {"Accept" "application/json", "x-apikey"
         (str "accessKey=" access-key ";secretKey=" secret-key)}
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

(defn tenable-sc-scan-status
  ""
  [access-key secret-key scan-result-id]
  (get-in
    (client/get (str "https://192.168.50.201/rest/scanResult/" scan-result-id "?fields=name%2Cdescription%2CdiagnosticAvailable%2Cowner%2CownerGroup%2CimportStatus%2CimportStart%2CimportFinish%2CimportDuration%2CioSyncStatus%2CioSyncStart%2CioSyncFinish%2CioSyncDuration%2CtotalIPs%2CscannedIPs%2CcompletedIPs%2CcompletedChecks%2CtotalChecks%2Cstatus%2CjobID%2CerrorDetails%2CdownloadAvailable%2CdataFormat%2CfinishTime%2CdownloadFormat%2CscanID%2Crunning%2CimportErrorDetails%2CioSyncErrorDetails%2CinitiatorID%2CstartTime%2Crepository%2Cdetails%2CtimeoutAction%2CrolloverSchedule%2Cprogress%2CdataSourceID%2CresultType%2CresultSource%2CscanDuration%2CcanManage%2CcanUse%2CSCI%2CagentScanUUID%2CagentScanContainerUUID%2CresultsSyncID%2CretrievalStatus%2Corganization") {:insecure? true
    :as :json
    :headers {"Accept" "application/json",
    "x-apikey" (str "accessKey=" access-key ";secretKey=" secret-key)}})
    [:body :response :importStatus]))

(defn create-run-destroy
  ""
  [access-key secret-key username password]
  (let [policy-id (tenable-sc-create-policy access-key secret-key "My scan-policy" 1000004)]
    (println (str "Creating new Advanced Scan Policy with ID " policy-id))
    (let [credential-id (tenable-sc-create-credential access-key secret-key
        (generate-credential-object-ssh "My SSH credential" username password))]
      (println (str "Creating new SSH crednetial object with ID " credential-id))
      (let [new-scan (tenable-sc-create-scan access-key secret-key
          "My Active Scan" policy-id "192.168.8.161" credential-id)]
        (println (str "Creating scan with Active Scan ID " new-scan))
        (let [scan-result-id
            (tenable-sc-launch-scan access-key secret-key new-scan)]
          (println (str "Launching scan with scan result ID "
            scan-result-id))

          (loop [time-elapsed 0]
            (if (> time-elapsed (* 5 60 1000))
              true
              (if (= (tenable-sc-scan-status access-key secret-key
                  scan-result-id) "Finished")
                (do
                  (println (str "Scan " scan-result-id " finished."))
                  (recur (* 6 60 1000)))
                (do
                  (println "Scan " scan-result-id " still running. Waiting 30 seconds before checking scan status again.")
                  (Thread/sleep (* 30 1000))
                  (recur (+ time-elapsed (* 30 1000))))))))

        (println (str "Deleting Active Scan ID " new-scan))
        (tenable-sc-delete-active-scan access-key secret-key new-scan))
        (println (str "Deleting Credential object ID " credential-id))
        (tenable-sc-delete-credential access-key secret-key credential-id))
        (println (str "Deleting scan policy ID " policy-id))
        (tenable-sc-delete-scan-policy access-key secret-key policy-id)))

(defn -main
  "Make a simple http request."
  [& args]
  (let [keys (clojure.string/split-lines
    (slurp "src/clj_tenable_api/tenable_sc_keys.txt"))]
    (create-run-destroy (nth keys 0) (nth keys 1) "test-user" "password")
    ))
