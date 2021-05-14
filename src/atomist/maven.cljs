(ns atomist.maven
  (:require [cljs-node-io.core :as io]
            [atomist.async :refer [go-safe <?]]
            [atomist.project :refer [expand-java-project]]
            [cljs.core.async :refer [<!] :refer-macros [go]]
            [cljs-node-io.proc :as proc]
            [clojure.string :as s]
            [atomist.cljs-log :as log]
            [goog.string :as gstring]
            [goog.string.format]
            [clojure.edn :as edn]))

(set! *warn-on-infer* false)

(defn get-jars [basedir scan-dir]
  (go-safe
   (when (.exists basedir)
     (let [[err stdout stderr] (<? (proc/aexec "mvn dependency:build-classpath" {:cwd (.getPath basedir)}))]
       (when err
         (log/error stderr)
         (throw (ex-info "failed to run `clj -Spath`" {:stderr stderr})))
       (doseq [path (s/split 
                      (let [[_ cp] (re-find #"Dependencies classpath:\n([^\n]+)" stdout)] cp) 
                      #":")]
         (<? (proc/aexec (gstring/format "cp %s %s" path (.getPath scan-dir)))))))))

(defmethod expand-java-project :pom.xml
  [request f]
  (go-safe
    (let [scan-dir (io/file (.getParentFile f) "to-scan")]
      (.mkdirs scan-dir)
      (<? (get-jars (.getParentFile f) scan-dir))
      {:project-file f
       :path scan-dir})))
