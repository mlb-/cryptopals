(ns cryptopals.core-test
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]))

;;; http://cryptopals.com/sets/1/challenges/1/
(deftest set-1-challenge-1
  (testing "Convert hex to base64"
    (is (= (->> "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
                decode-hex-str
                (into-array Byte/TYPE)
                javax.xml.bind.DatatypeConverter/printBase64Binary)
           "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"))

    (is (= (->> "Man"
                .getBytes
                encode-base64)
           "TWFu"))

    (is (= (->> "sure."
                (iterate butlast)
                (take-while (complement nil?))
                (map #(map byte %))
                (map encode-base64))
           ["c3VyZS4=" "c3VyZQ==" "c3Vy" "c3U=" "cw=="]))

    (is (= (hex->base64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
           "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"))))

;;; http://cryptopals.com/sets/1/challenges/2/
(deftest set-1-challenge-2
  (testing "XOR"
    (is (= (xor (decode-hex-str "1c0111001f010100061a024b53535009181c")
                (decode-hex-str "686974207468652062756c6c277320657965"))
           (decode-hex-str "746865206b696420646f6e277420706c6179")))))

;;; http://cryptopals.com/sets/1/challenges/3/
(deftest set-1-challenge-3
  (testing "Single character xor"
    (is (= (bruteforce-repeating-singlechar-xor-from-hex "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
           (map byte "Cooking MC's like a pound of bacon"))))
  (testing "Bigram lookup"
    (is (= (bigram-PDF (byte \a) (byte \b))
           0.0228302))))

