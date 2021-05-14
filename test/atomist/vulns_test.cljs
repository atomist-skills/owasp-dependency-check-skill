(ns atomist.vulns-test
  (:require [cljs.pprint :refer [pprint]]
            [atomist.main :refer [transact-vulns is-cve?]]
            [cljs-node-io.core :as io]
            [atomist.json :as json]
            [clojure.edn :as edn]
            [cljs.core.async :refer [<!] :refer-macros [go]]
            [cljs.test :refer-macros [deftest is async]]
            ))

(defn do-nothing [& args] (go true))

(defn js-obj->entities [& args]
  (go (-> args
          first
          (js->clj :keywordize-keys true)
          :entities
          (edn/read-string))))

(defn print-all [& args] (go
                           (let [entities (<! (apply js-obj->entities args))]
                             (when (some is-cve? entities)
                               (cljs.pprint/pprint entities)))
                           true))

(enable-console-print!)

(deftest vuln-tests
  (async
   done
   (go
     (<! ((transact-vulns #(go (is (= 0 (-> % :atomist/status :code))) %))
          {:correlation_id "corrid"
           :sendreponse print-all
           :atomist/file {:entity-type :git.commit/file
                          :entity "$project-file"
                          :git.file/sha "sha"
                          :git.file/path "project.clj"}
           :atomist/file-ref "$project-file"
           :atomist/org {:git.provider/url "url"}
           :atomist/repo {:git.repo/source-id "source-id"}
           :atomist/commit {:git.commit/sha "sha"}
           :atomist/dependency-report (json/->obj (io/slurp "dependency-check-report.json"))}))
     (done))))

(comment
  (pprint
   (-> (io/slurp "dependency-check-report.json")
       (json/->obj)
       :dependencies
       (as-> deps (->> deps
                       (map (fn [dep]
                              (select-keys dep [:vulnerabilities :vulnerabilityIds :packages :fileName])))
                       (map (fn [dep]
                              (-> dep
                                  (merge
                                   (when (seq (:vulnerabilities dep))
                                     {:cve-count (count (:vulnerabilities dep))}))
                                  (dissoc :vulnerabilities)))) (map #(->> %)))))))
