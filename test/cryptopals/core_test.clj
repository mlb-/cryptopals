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

;;; http://cryptopals.com/sets/1/challenges/4/
(deftest set-1-challenge-4
  (testing "Find the plaintext given multiple candidates."
    (is (= (->> "4.txt"
                clojure.java.io/resource
                clojure.java.io/reader
                line-seq
                bruteforce-repeating-singlechar-xor-from-hex-collection)
           (map byte "Now that the party is jumping\n")))))

;;; http://cryptopals.com/sets/1/challenges/5/
(deftest set-1-challenge-5
  (testing "Repeating-key XOR"
    (is (= (repeating-key-xor (map byte "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal")
                              (map byte "ICE"))
           (decode-hex-str "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")))))

;;; http://cryptopals.com/sets/1/challenges/6/

(deftest set-1-challenge-6
  (testing "Decode base64"
    (is (= (decode-base64 "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
           (decode-hex-str "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))

    (is (= (decode-base64 "TWFu")
           (map byte "Man")))

    (is (= (map decode-base64 ["c3VyZS4=" "c3VyZQ==" "c3Vy" "c3U=" "cw=="])
           (->> "sure."
                (iterate butlast)
                (take-while (complement nil?))
                (map #(map byte %))))))

  (testing "Hamming distance"
    (is (= (hamming-distance (map byte "this is a test")
                             (map byte "wokka wokka!!!"))
           37)))
  (testing "Break repeating key XOR"
    (is (= (break-repeating-key-xor (->> "6.txt"
                                         clojure.java.io/resource
                                         clojure.java.io/reader
                                         line-seq
                                         (apply str)
                                         decode-base64))
           (map byte "Terminator X: Bring the noise")))))
