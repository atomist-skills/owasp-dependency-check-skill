(ns atomist.scan-t
  (:require [cljs.core.async :refer [<!] :refer-macros [go]]
            [atomist.main :refer [scan-all]]
            [atomist.async :refer-macros [go-safe]]
            [cljs.pprint :refer [pprint]]
            [cljs.test :refer-macros [deftest is async]]
            [cljs-node-io.proc :as proc]
            [clojure.string :as s]))

(enable-console-print!)

(defn async-count-stdout-lines
  [command]
  (go (let [[_ stdout _] (<! (proc/aexec command))]
         (count (s/split stdout "\n")))))

(deftest scannable-tests
  (async
   done
   (go
     (<!
      ((scan-all
        #(go-safe %)
        #(go-safe
          (pprint (:atomist/scannable %))
          (is (not (instance? js/Error (:atomist/scannable %))))
          (is (= 179 (<! (async-count-stdout-lines "ls /Users/slim/atmhq/bot-service/to-scan"))))
          %))
       {:subscription
        {:data [[{:git.commit/file [{:git.file/path "project.clj"}]} {}]]}
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
        {:data [[{:git.commit/file [{:git.file/path "pom.xml"}]} {}]]}
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
        {:data [[{:git.commit/file [{:git.file/path "deps.edn"}]} {}]]}
        :project
        {:path "/Users/slim/skills/cljfmt-skill"}}))
     (done))))
 
