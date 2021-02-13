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
  (<! (get-jars (io/file "/Users/slim/atmhq/bot-service") (io/file "jar-lib"))))
