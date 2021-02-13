;; Copyright © 2021 Atomist, Inc.
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

(ns atomist.lein
  (:require [cljs-node-io.core :as io]
            [atomist.async :refer [go-safe <?]]
            [cljs.core.async :refer [<!] :refer-macros [go]]
            [cljs-node-io.proc :as proc]
            [clojure.string :as s]
            [goog.string :as gstring]
            [goog.string.format]))

(defn get-jars [project-dir target-dir]
  (go-safe
   (when (.exists project-dir)
     (.mkdirs target-dir)
     (let [[stderr stdout err] (<? (proc/aexec "lein cp" {:cwd (.getPath project-dir)}))]
        (doseq [path (s/split stdout #":")]
          (<? (proc/aexec (gstring/format "cp %s %s" path (.getPath target-dir)))))))))

(go
  (<! (get-jars (io/file "/Users/slim/atmhq/bot-service") (io/file "jar-lib"))) )
