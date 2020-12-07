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
            [atomist.github]))

(defn custom-middleware [handler]
  (fn [request]
    (go
      (log/info "do something useful here")
      (<! (handler request)))))

(defn ^:export handler
  [data sendreponse]
  (api/make-request
   data
   sendreponse
   (-> (api/finished :message "----> event handler finished")
       (custom-middleware)
       (api/log-event)
       (api/status))))
