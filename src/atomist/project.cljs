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

