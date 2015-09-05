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

(def hex->base64
  "Convert a hex encoded string to a base64 encoded string."
  (comp encode-base64
        decode-hex-str))

(def xor
  "Byte-wise XOR"
  (partial map bit-xor))

(def letter-PDF
  "Character frequency map of the alphabet (and space) for English.
    See: http://www.data-compression.com/english.html"
  (zipmap (concat (inclusive-char-range \a \z)
                  [(byte \space)])
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

(defn bruteforce-singlechar-xor
  "Given a series of XOR encrypted bytes, bruteforce the plaintext by
  heuristically grading the statistical likelyhood it is English."
  [cipher-bytes]
  (->> (range (inc Byte/MAX_VALUE))
       (map #(repeat %))
       (map #(xor cipher-bytes %))
       (map (juxt grade-english identity))
       (sort-by first)
       first
       second))

(def bruteforce-repeating-singlechar-xor-from-hex
  (comp bruteforce-singlechar-xor
        decode-hex-str))
