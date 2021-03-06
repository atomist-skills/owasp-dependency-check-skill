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

(ns atomist.scan-t
  (:require [cljs.core.async :refer [<!] :refer-macros [go]]
            [atomist.main :refer [scan-all]]
            [atomist.async :refer-macros [go-safe]]
            [goog.string :as gstring]
            [goog.string.format]
            [cljs.pprint :refer [pprint]]
            [cljs.test :refer-macros [deftest is async]]
            [cljs-node-io.proc :as proc]
            [clojure.string :as s]
            [atomist.lein :as lein]))

(enable-console-print!)

(defn async-count-stdout-lines
  [command]
  (go (let [[_ stdout _] (<! (proc/aexec command))]
         (count (s/split stdout "\n")))))

(deftest scan-clj-tests
  (async
   done
   (go
     (<! ((-> #(go-safe
                (println "finished:back " %)
                (is (= 0 (-> % :atomist/status :code)))
                (is (s/starts-with? (-> % :atomist/status :reason) "scanned 1 projects"))
                %)
              (scan-all #(go-safe
                          (println "scan " %)
                          %))
              (lein/add-lein-profiles))
          {:subscription {:result [[{:git.commit/file
                                     [{:git.file/path "atomist.sh" :git.file/sha "7e1200644d9081b58819051f188b626d14b88dde"}
                                      {:git.file/path "docker/Dockerfile.gcr" :git.file/sha "847a86d7a63c6d8d92eb7b7ef49c9f35b774fbd1"}
                                      {:git.file/path "project.clj" :git.file/sha "ad17799ed2d1a95bfaa4c452ceddbebc688ac774"}]}]]}
           :project {:path "/Users/slim/atmhq/view-service"}}))
     (done))))

(deftest unscannable-tests
  (async
   done
   (go
     (<! ((scan-all
           #(go-safe
             (println "back " %)
             (is (= 0 (-> % :atomist/status :code)))
             (is (s/starts-with? (-> % :atomist/status :reason) "scanned 0 projects"))
             %)
           #(go-safe
             (println "scan " %)
             %))
          {:subscription {:result [[{:git.commit/file []}]]}
           :project {:path "/Users/slim/repo/demo-spring"}}))
     (<! ((scan-all
           #(go-safe
             (println "back " %)
             (is (= 0 (-> % :atomist/status :code))) %)
           #(go-safe
             (println "scan " %)
             %))
          {:subscription {:result [[{:git.commit/file [{:git.file/path "unscannable"}]}]]}
           :project {:path "/Users/slim/repo/demo-spring"}}))
     (done))))

(deftest scannable-tests
  (async
   done
   (go
     (<!
      ((scan-all
        #(go-safe 
           (is (s/starts-with? (-> % :atomist/status :reason) (gstring/format "scanned %d projects" 1)))
           %)
        #(go-safe
          (pprint (:atomist/scannable %))
          (is (not (instance? js/Error (:atomist/scannable %))))
          (is (= 179 (<! (async-count-stdout-lines "ls /Users/slim/atmhq/bot-service/to-scan"))))
          %))
       {:subscription
        {:result [[{:git.commit/file [{:git.file/path "project.clj"}]} {}]]}
        :project
        {:path "/Users/slim/atmhq/bot-service"}}))
     (<!
      ((scan-all
        #(go-safe %)
        #(go-safe
          (pprint (:atomist/scannable %))
          (is (not (instance? js/Error (:atomist/scannable %))))
          (is (= 46 (<! (async-count-stdout-lines "ls /Users/slim/repo/demo-spring/to-scan"))))
          %))
       {:subscription
        {:result [[{:git.commit/file [{:git.file/path "pom.xml"}]} {}]]}
        :project
        {:path "/Users/slim/repo/demo-spring"}}))
     (<!
      ((scan-all
        #(go-safe 
           (println "returns " %)
           (is (= 0 (-> % :atomist/status :code)) "deps.edn scanning threw an exception") 
           %)
        #(go-safe
          (pprint (:atomist/scannable %))
          (is (not (instance? js/Error (:atomist/scannable %))))
          (is (= 48 (<! (async-count-stdout-lines "ls /Users/slim/skills/cljfmt-skill/to-scan"))))
          %))
       {:subscription
        {:result [[{:git.commit/file [{:git.file/path "deps.edn"}]} {}]]}
        :project
        {:path "/Users/slim/skills/cljfmt-skill"}}))
     (done))))
 
