;; Copyright © 2020 Atomist, Inc.
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns atomist.main
  (:require [atomist.api :as api]
            [cljs.pprint :refer [pprint]]
            [cljs.core.async :refer [<!] :refer-macros [go]]
            [goog.string.format]
            [clojure.data]
            [atomist.cljs-log :as log]
            [atomist.github]
            [atomist.container :as container]))

(defn create-ref-from-event
  [handler]
  (fn [request]
    (go
     (let [{:git.commit/keys [repo sha]} (-> request :subscription :result first first)]
       (<! (handler (assoc request :ref {:repo (:git.repo/name repo)
                                         :owner (-> repo :git.repo/org :git.org/name)
                                         :sha sha}
                                   :token (-> repo :git.repo/org :github.org/installation-token))))))))

(defn run-scan [handler]
  (fn [request]
    (go
      (log/info "do something useful here")
      (<! (handler request)))))

(defn ^:export handler
  [& args]
  ((-> (api/finished :message "----> event handler finished")
       (run-scan)
       (api/clone-ref)
       (api/with-github-check-run :name "owasp-dependency-check")
       (create-ref-from-event)
       (api/log-event)
       (api/status)
       (container/mw-make-container-request)) {}))
