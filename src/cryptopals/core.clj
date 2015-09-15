(ns cryptopals.core)

(def decode-hex-str
  "Translate a hex string into the ordinal character
  values (represented as Java Bytes)."
  (comp (partial map (comp #(Integer/parseInt % 16)
                           (partial apply str)))
        (partial partition 2)))

(defn- byte-accumulator
  "Build up the value of multiple bytes."
  [acc byte]
  (+ byte
     (bit-shift-left acc 8)))

(def sixbit-extraction
  "Extract 4 six-bit values from a 24-bit value."
  (comp first
        #(reduce (fn [[acc block] _]
                   [(conj acc (bit-and block 63))
                    (bit-shift-right block 6)])
                 [(list) %]
                 (range 4))))

(defn sixbit-accumulator
  [acc sixbit]
  (+ sixbit
     (bit-shift-left acc 6)))

(def byte-extraction
  "Extract byte values from a 24-bit value."
  (comp first
        #(reduce (fn [[acc block] _]
                   [(conj acc (bit-and block 127))
                    (bit-shift-right block 8)])
                 [(list) %]
                 (range 3))))

(defn inclusive-char-range
  [beginning ending]
  (map byte (range (byte beginning)
                   (inc (byte ending)))))

(def base64-characters
  (concat (inclusive-char-range \A \Z)
          (inclusive-char-range \a \z)
          (inclusive-char-range \0 \9)
          [\+ \/]))

(defn encode-base64
  [chars]
  (let [;; Calculate the required amount of padding
        padded-bytes (mod (count chars) 3)
        replace-chars (mod (- 3 padded-bytes) 3)
        padding (repeat replace-chars \=)
        ;; Split up the payload into groups of 3
        byte-blocks (partition 3 3 [0 0] chars)
        ;; Translate each group into base64 characters
        xfs (comp (map #(reduce byte-accumulator %))
                  (mapcat sixbit-extraction)
                  (map #(nth base64-characters %))
                  (map char))
        ;; Drop the appropriate number of trailing "A"s
        base64 (->> byte-blocks
                    (sequence xfs)
                    (drop-last replace-chars)
                    vec)]
    ;; Append appropriate amount of padding
    (->> padding
         (apply conj base64)
         (apply str))))

(defn decode-base64
  [encoded-str]
  (let [without-padding (->> encoded-str
                             (take-while #(not (= \= %))))
        not-padded-chars (mod (count without-padding) 4)
        padded-chars (mod (- 4 not-padded-chars) 4)
        byte-blocks (->> without-padding
                         (map byte)
                         (map #(.indexOf base64-characters %))
                         (partition 4 4 [0 0 0])
                         (map #(reduce sixbit-accumulator %))
                         (mapcat byte-extraction)
                         (drop-last padded-chars))]
    byte-blocks))

(def hex->base64
  "Convert a hex encoded string to a base64 encoded string."
  (comp encode-base64
        decode-hex-str))

(def xor
  "Byte-wise XOR"
  (partial map bit-xor))

(def a-to-z-and-space
  (concat (inclusive-char-range \a \z)
          [(byte \space)]))

(def letter-PDF
  "Character frequency map of the alphabet (and space) for English.
    See: http://www.data-compression.com/english.html"
  (zipmap a-to-z-and-space
          [0.0651738 0.0124248 0.0217339 0.0349835 0.1041442 0.0197881
           0.0158610 0.0492888 0.0558094 0.0009033 0.0050529 0.0331490
           0.0202124 0.0564513 0.0596302 0.0137645 0.0008606 0.0497563
           0.0515760 0.0729357 0.0225134 0.0082903 0.0171272 0.0013692
           0.0145984 0.0007836 0.1918182]))

(defn grade-english
  "Given a collection of letters represented as bytes, normalize the
  frequency of each letter present in the sample. Compare this
  distribution against `letter-PDF` and return the average
  drift."
  [byte-collection]
  (let [n (count byte-collection)
        actual-frequencies (->> byte-collection
                                (replace (zipmap (inclusive-char-range \A \Z)
                                                 (inclusive-char-range \a \z)))
                                frequencies)]
    (/ (->> letter-PDF
            (map (fn [[letter expected-frequency]]
                   (let [actual-frequency (actual-frequencies letter 0)
                         expected-frequency (* expected-frequency n)]
                     (Math/abs (- expected-frequency
                                  actual-frequency)))))
            (apply +))
       (count letter-PDF))))

(defn bigram-line-formatter
  [line]
  (->> (.split line " ")
       (mapv #(Double/parseDouble %))))

(def bigram-PDF-data
  "This is a 27x27 bigram frequency lookup table based on English
  text. Ordered by a-z, then space."
  (->> "bigrams"
       clojure.java.io/resource
       clojure.java.io/reader
       line-seq
       (mapv bigram-line-formatter)))

(defn bigram-PDF
  "Given two characters represented by Java Bytes, return the
  probability that `y` follows `x`."
  [x y]
  (let [x (.indexOf a-to-z-and-space x)
        y (.indexOf a-to-z-and-space y)]
    (when (and (not (neg? x))
               (not (neg? y)))
      (-> bigram-PDF-data
          (nth x)
          (nth y)))))

(defn grade-english-2
  [byte-collection]
  (let [n (count byte-collection)
        actual-frequencies (->> byte-collection
                                (replace (zipmap (inclusive-char-range \A \Z)
                                                 (inclusive-char-range \a \z)))
                                (partition 2 1)
                                frequencies)
        bigram-search-space (for [x a-to-z-and-space
                                  y a-to-z-and-space]
                              [x y])]
    (/ (->> bigram-search-space
            (map (fn [[x y]]
                   (let [expected (* n
                                     (bigram-PDF x y))
                         actual (actual-frequencies [x y] 0)]
                     (Math/abs (- expected
                                  actual)))))
            (apply +))
       (Math/pow (count bigram-search-space) 2))))

(defn generate-single-char-xor-candidates
  "Given a `cipher-bytes` generate all potential candidates (and their
  `grade-english` value) if encoded by a single character XOR."
  [cipher-bytes]
  (->> (range (inc Byte/MAX_VALUE))
       (map #(repeat %))
       (map #(xor cipher-bytes %))
       (map (juxt grade-english identity))))

(def select-best-candidate
  (comp second
        first
        #(sort-by first %)))

(def bruteforce-singlechar-xor
  "Given a series of XOR encrypted bytes, bruteforce the plaintext by
  heuristically grading the statistical likelyhood it is English."
  (comp select-best-candidate
        generate-single-char-xor-candidates))

(def bruteforce-repeating-singlechar-xor-from-hex
  (comp bruteforce-singlechar-xor
        decode-hex-str))

(def bruteforce-repeating-singlechar-xor-from-hex-collection
  "Same as `bruteforce-repeating-singlechar-xor-from-hex`, but take in
  a collection of hex encoded sequences and return the candidate which
  was most likely encrypted with a repeating character XOR."
  (comp select-best-candidate
        #(mapcat generate-single-char-xor-candidates %)
        #(map decode-hex-str %)))

(defn repeating-key-xor
  [bytes repeating-key]
  (xor bytes
       (cycle repeating-key)))

(defn hamming-distance
  [& bytes-collection]
  (->> (apply xor bytes-collection)
       (map #(Integer/bitCount %))
       (apply +)))

(let [encrypted-bytes (->> "6.txt"
                           clojure.java.io/resource
                           clojure.java.io/reader
                           line-seq
                           (apply str)
                           decode-base64)
      keysizes (range 2 41)
      average-hamming-distance (fn [keysize]
                                 (->> encrypted-bytes
                                      (partition keysize)
                                      (take 2)
                                      (apply (comp #(/ % keysize)
                                                   hamming-distance))))
      keysize-candidate (->> keysizes
                             ;; transform keysize -> [edit-distance keysize]
                             (map (juxt average-hamming-distance
                                        identity))
                             select-best-candidate)]
  keysize-candidate)
