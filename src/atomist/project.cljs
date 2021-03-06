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

(ns atomist.project
  (:require [cljs.core.async :refer-macros [go]])
  )

(set! *warn-on-infer* false)

(defn f->type [_ f]
  (cond
    (= "pom.xml" (.getName f)) :pom.xml
    (= "project.clj" (.getName f)) :leiningen
    (= "deps.edn" (.getName f)) :deps.edn))

(defmulti expand-java-project f->type)

(defmethod expand-java-project :default
  [_ _]
  (go
    {:atomist/skipped true}))

