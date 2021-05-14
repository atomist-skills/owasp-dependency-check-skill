(ns atomist.project)

(set! *warn-on-infer* false)

(defn f->type [_ f]
  (cond
    (= "pom.xml" (.getName f)) :pom.xml
    (= "project.clj" (.getName f)) :leiningen
    (= "deps.edn" (.getName f)) :deps.edn))

(defmulti expand-java-project f->type)
