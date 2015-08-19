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

(def base64-characters
  (concat (map char (range (byte \A)
                           (inc (byte \Z))))
          (map char (range (byte \a)
                           (inc (byte \z))))
          (map char (range (byte \0)
                           (inc (byte \9))))
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
                  (map #(nth base64-characters %)))
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
