//ref: https://github.com/sausheong/gonb

package errorpageclassifier

import (
	"bytes"
	"encoding/gob"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/kljensen/snowball"
)

var (
	cleaner   = regexp.MustCompile(`[^\w\s]`)
	stopWords = map[string]struct{}{"a": {}, "able": {}, "about": {}, "above": {}, "abroad": {}, "according": {}, "accordingly": {}, "across": {}, "actually": {}, "adj": {}, "after": {}, "afterwards": {}, "again": {}, "against": {}, "ago": {}, "ahead": {}, "ain't": {}, "all": {}, "allow": {}, "allows": {}, "almost": {}, "alone": {}, "along": {}, "alongside": {}, "already": {}, "also": {}, "although": {}, "always": {}, "am": {}, "amid": {}, "amidst": {}, "among": {}, "amongst": {}, "an": {}, "and": {}, "another": {}, "any": {}, "anybody": {}, "anyhow": {}, "anyone": {}, "anything": {}, "anyway": {}, "anyways": {}, "anywhere": {}, "apart": {}, "appear": {}, "appreciate": {}, "appropriate": {}, "are": {}, "aren't": {}, "around": {}, "as": {}, "a's": {}, "aside": {}, "ask": {}, "asking": {}, "associated": {}, "at": {}, "available": {}, "away": {}, "awfully": {}, "b": {}, "back": {}, "backward": {}, "backwards": {}, "be": {}, "became": {}, "because": {}, "become": {}, "becomes": {}, "becoming": {}, "been": {}, "before": {}, "beforehand": {}, "begin": {}, "behind": {}, "being": {}, "believe": {}, "below": {}, "beside": {}, "besides": {}, "best": {}, "better": {}, "between": {}, "beyond": {}, "both": {}, "brief": {}, "but": {}, "by": {}, "c": {}, "came": {}, "can": {}, "cannot": {}, "cant": {}, "can't": {}, "caption": {}, "cause": {}, "causes": {}, "certain": {}, "certainly": {}, "changes": {}, "clearly": {}, "c'mon": {}, "co": {}, "co.": {}, "com": {}, "come": {}, "comes": {}, "concerning": {}, "consequently": {}, "consider": {}, "considering": {}, "contain": {}, "containing": {}, "contains": {}, "corresponding": {}, "could": {}, "couldn't": {}, "course": {}, "c's": {}, "currently": {}, "d": {}, "dare": {}, "daren't": {}, "definitely": {}, "described": {}, "despite": {}, "did": {}, "didn't": {}, "different": {}, "directly": {}, "do": {}, "does": {}, "doesn't": {}, "doing": {}, "done": {}, "don't": {}, "down": {}, "downwards": {}, "during": {}, "e": {}, "each": {}, "edu": {}, "eg": {}, "eight": {}, "eighty": {}, "either": {}, "else": {}, "elsewhere": {}, "end": {}, "ending": {}, "enough": {}, "entirely": {}, "especially": {}, "et": {}, "etc": {}, "even": {}, "ever": {}, "evermore": {}, "every": {}, "everybody": {}, "everyone": {}, "everything": {}, "everywhere": {}, "ex": {}, "exactly": {}, "example": {}, "except": {}, "f": {}, "fairly": {}, "far": {}, "farther": {}, "few": {}, "fewer": {}, "fifth": {}, "first": {}, "five": {}, "followed": {}, "following": {}, "follows": {}, "for": {}, "forever": {}, "former": {}, "formerly": {}, "forth": {}, "forward": {}, "found": {}, "four": {}, "from": {}, "further": {}, "furthermore": {}, "g": {}, "get": {}, "gets": {}, "getting": {}, "given": {}, "gives": {}, "go": {}, "goes": {}, "going": {}, "gone": {}, "got": {}, "gotten": {}, "greetings": {}, "h": {}, "had": {}, "hadn't": {}, "half": {}, "happens": {}, "hardly": {}, "has": {}, "hasn't": {}, "have": {}, "haven't": {}, "having": {}, "he": {}, "he'd": {}, "he'll": {}, "hello": {}, "help": {}, "hence": {}, "her": {}, "here": {}, "hereafter": {}, "hereby": {}, "herein": {}, "here's": {}, "hereupon": {}, "hers": {}, "herself": {}, "he's": {}, "hi": {}, "him": {}, "himself": {}, "his": {}, "hither": {}, "hopefully": {}, "how": {}, "howbeit": {}, "however": {}, "hundred": {}, "i": {}, "i'd": {}, "ie": {}, "if": {}, "ignored": {}, "i'll": {}, "i'm": {}, "immediate": {}, "in": {}, "inasmuch": {}, "inc": {}, "inc.": {}, "indeed": {}, "indicate": {}, "indicated": {}, "indicates": {}, "inner": {}, "inside": {}, "insofar": {}, "instead": {}, "into": {}, "inward": {}, "is": {}, "isn't": {}, "it": {}, "it'd": {}, "it'll": {}, "its": {}, "it's": {}, "itself": {}, "i've": {}, "j": {}, "just": {}, "k": {}, "keep": {}, "keeps": {}, "kept": {}, "know": {}, "known": {}, "knows": {}, "l": {}, "last": {}, "lately": {}, "later": {}, "latter": {}, "latterly": {}, "least": {}, "less": {}, "lest": {}, "let": {}, "let's": {}, "like": {}, "liked": {}, "likely": {}, "likewise": {}, "little": {}, "look": {}, "looking": {}, "looks": {}, "low": {}, "lower": {}, "ltd": {}, "m": {}, "made": {}, "mainly": {}, "make": {}, "makes": {}, "many": {}, "may": {}, "maybe": {}, "mayn't": {}, "me": {}, "mean": {}, "meantime": {}, "meanwhile": {}, "merely": {}, "might": {}, "mightn't": {}, "mine": {}, "minus": {}, "miss": {}, "more": {}, "moreover": {}, "most": {}, "mostly": {}, "mr": {}, "mrs": {}, "much": {}, "must": {}, "mustn't": {}, "my": {}, "myself": {}, "n": {}, "name": {}, "namely": {}, "nd": {}, "near": {}, "nearly": {}, "necessary": {}, "need": {}, "needn't": {}, "needs": {}, "neither": {}, "never": {}, "neverf": {}, "neverless": {}, "nevertheless": {}, "new": {}, "next": {}, "nine": {}, "ninety": {}, "no": {}, "nobody": {}, "non": {}, "none": {}, "nonetheless": {}, "noone": {}, "no-one": {}, "nor": {}, "normally": {}, "not": {}, "nothing": {}, "notwithstanding": {}, "novel": {}, "now": {}, "nowhere": {}, "o": {}, "obviously": {}, "of": {}, "off": {}, "often": {}, "oh": {}, "ok": {}, "okay": {}, "old": {}, "on": {}, "once": {}, "one": {}, "ones": {}, "one's": {}, "only": {}, "onto": {}, "opposite": {}, "or": {}, "other": {}, "others": {}, "otherwise": {}, "ought": {}, "oughtn't": {}, "our": {}, "ours": {}, "ourselves": {}, "out": {}, "outside": {}, "over": {}, "overall": {}, "own": {}, "p": {}, "particular": {}, "particularly": {}, "past": {}, "per": {}, "perhaps": {}, "placed": {}, "please": {}, "plus": {}, "possible": {}, "presumably": {}, "probably": {}, "provided": {}, "provides": {}, "q": {}, "que": {}, "quite": {}, "qv": {}, "r": {}, "rather": {}, "rd": {}, "re": {}, "really": {}, "reasonably": {}, "recent": {}, "recently": {}, "regarding": {}, "regardless": {}, "regards": {}, "relatively": {}, "respectively": {}, "right": {}, "round": {}, "s": {}, "said": {}, "same": {}, "saw": {}, "say": {}, "saying": {}, "says": {}, "second": {}, "secondly": {}, "see": {}, "seeing": {}, "seem": {}, "seemed": {}, "seeming": {}, "seems": {}, "seen": {}, "self": {}, "selves": {}, "sensible": {}, "sent": {}, "serious": {}, "seriously": {}, "seven": {}, "several": {}, "shall": {}, "shan't": {}, "she": {}, "she'd": {}, "she'll": {}, "she's": {}, "should": {}, "shouldn't": {}, "since": {}, "six": {}, "so": {}, "some": {}, "somebody": {}, "someday": {}, "somehow": {}, "someone": {}, "something": {}, "sometime": {}, "sometimes": {}, "somewhat": {}, "somewhere": {}, "soon": {}, "sorry": {}, "specified": {}, "specify": {}, "specifying": {}, "still": {}, "sub": {}, "such": {}, "sup": {}, "sure": {}, "t": {}, "take": {}, "taken": {}, "taking": {}, "tell": {}, "tends": {}, "th": {}, "than": {}, "thank": {}, "thanks": {}, "thanx": {}, "that": {}, "that'll": {}, "thats": {}, "that's": {}, "that've": {}, "the": {}, "their": {}, "theirs": {}, "them": {}, "themselves": {}, "then": {}, "thence": {}, "there": {}, "thereafter": {}, "thereby": {}, "there'd": {}, "therefore": {}, "therein": {}, "there'll": {}, "there're": {}, "theres": {}, "there's": {}, "thereupon": {}, "there've": {}, "these": {}, "they": {}, "they'd": {}, "they'll": {}, "they're": {}, "they've": {}, "thing": {}, "things": {}, "think": {}, "third": {}, "thirty": {}, "this": {}, "thorough": {}, "thoroughly": {}, "those": {}, "though": {}, "three": {}, "through": {}, "throughout": {}, "thru": {}, "thus": {}, "till": {}, "to": {}, "together": {}, "too": {}, "took": {}, "toward": {}, "towards": {}, "tried": {}, "tries": {}, "truly": {}, "try": {}, "trying": {}, "t's": {}, "twice": {}, "two": {}, "u": {}, "un": {}, "under": {}, "underneath": {}, "undoing": {}, "unfortunately": {}, "unless": {}, "unlike": {}, "unlikely": {}, "until": {}, "unto": {}, "up": {}, "upon": {}, "upwards": {}, "us": {}, "use": {}, "used": {}, "useful": {}, "uses": {}, "using": {}, "usually": {}, "v": {}, "value": {}, "various": {}, "versus": {}, "very": {}, "via": {}, "viz": {}, "vs": {}, "w": {}, "want": {}, "wants": {}, "was": {}, "wasn't": {}, "way": {}, "we": {}, "we'd": {}, "welcome": {}, "well": {}, "we'll": {}, "went": {}, "were": {}, "we're": {}, "weren't": {}, "we've": {}, "what": {}, "whatever": {}, "what'll": {}, "what's": {}, "what've": {}, "when": {}, "whence": {}, "whenever": {}, "where": {}, "whereafter": {}, "whereas": {}, "whereby": {}, "wherein": {}, "where's": {}, "whereupon": {}, "wherever": {}, "whether": {}, "which": {}, "whichever": {}, "while": {}, "whilst": {}, "whither": {}, "who": {}, "who'd": {}, "whoever": {}, "whole": {}, "who'll": {}, "whom": {}, "whomever": {}, "who's": {}, "whose": {}, "why": {}, "will": {}, "willing": {}, "wish": {}, "with": {}, "within": {}, "without": {}, "wonder": {}, "won't": {}, "would": {}, "wouldn't": {}, "x": {}, "y": {}, "yes": {}, "yet": {}, "you": {}, "you'd": {}, "you'll": {}, "your": {}, "you're": {}, "yours": {}, "yourself": {}, "yourselves": {}, "you've": {}, "z": {}, "zero": {}}
)

type Sorted struct {
	Category    string
	Probability float64
}

// Classifier is what we use to classify documents
type Classifier struct {
	Words               map[string]map[string]int
	TotalWords          int
	CategoriesDocuments map[string]int
	TotalDocuments      int
	CategoriesWords     map[string]int
	Threshold           float64
}

// create and initialize the classifier
func NewClassifier(categories []string, threshold float64) *Classifier {
	classifier := &Classifier{
		Words:               make(map[string]map[string]int),
		TotalWords:          0,
		CategoriesDocuments: make(map[string]int),
		TotalDocuments:      0,
		CategoriesWords:     make(map[string]int),
		Threshold:           threshold,
	}

	for _, category := range categories {
		classifier.Words[category] = make(map[string]int)
		classifier.CategoriesDocuments[category] = 0
		classifier.CategoriesWords[category] = 0
	}
	return classifier
}

// create and initialize the classifier from a file
func NewClassifierFromFile(path string) (*Classifier, error) {
	classifier := &Classifier{}

	fl, err := os.Open(path)
	if err != nil {
		return classifier, err
	}
	defer fl.Close()

	return NewClassifierWithReader(fl)
}

// create and initialize the classifier from a file data
func NewClassifierFromFileData(data []byte) (*Classifier, error) {
	return NewClassifierWithReader(bytes.NewReader(data))
}

// create and initialize the classifier from a file data
func NewClassifierWithReader(reader io.Reader) (*Classifier, error) {
	classifier := &Classifier{}
	err := gob.NewDecoder(reader).Decode(classifier)
	if err != nil {
		return classifier, err
	}

	return classifier, nil
}

// save the classifier to a file
// func (c *Classifier) SaveClassifierToFile(path string) error {
// 	fl, err := os.Create(path)
// 	if err != nil {
// 		return err
// 	}
// 	defer fl.Close()

// 	err = gob.NewEncoder(fl).Encode(&c)
// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }

// Train the classifier
// func (c *Classifier) Train(category string, document string) {
// 	for word, count := range countWords(document) {
// 		c.Words[category][word] += count
// 		c.CategoriesWords[category] += count
// 		c.TotalWords += count
// 	}
// 	c.CategoriesDocuments[category]++
// 	c.TotalDocuments++
// }

// Classify a document
func (c *Classifier) Classify(document string) (category string) {
	// get all the probabilities of each category
	prob := c.Probabilities(document)

	// sort the categories according to probabilities
	var sp []Sorted
	for c, p := range prob {
		sp = append(sp, Sorted{c, p})
	}
	sort.Slice(sp, func(i, j int) bool {
		return sp[i].Probability > sp[j].Probability
	})

	// if the highest probability is above threshold select that
	if sp[0].Probability/sp[1].Probability > c.Threshold {
		category = sp[0].Category
	} else {
		category = "other"
	}

	return
}

// Probabilities of each category
func (c *Classifier) Probabilities(document string) (p map[string]float64) {
	p = make(map[string]float64)
	for category := range c.Words {
		p[category] = c.pCategoryDocument(category, document)
	}
	return
}

// p (document | category)
func (c *Classifier) pDocumentCategory(category string, document string) (p float64) {
	p = 1.0
	for word := range countWords(document) {
		p = p * c.pWordCategory(category, word)
	}
	return p
}

func (c *Classifier) pWordCategory(category string, word string) float64 {
	return float64(c.Words[category][stem(word)]+1) / float64(c.CategoriesWords[category])
}

// p (category)
func (c *Classifier) pCategory(category string) float64 {
	return float64(c.CategoriesDocuments[category]) / float64(c.TotalDocuments)
}

// p (category | document)
func (c *Classifier) pCategoryDocument(category string, document string) float64 {
	return c.pDocumentCategory(category, document) * c.pCategory(category)
}

// clean up and split words in document, then stem each word and count the occurrence
func countWords(document string) (wordCount map[string]int) {
	cleaned := cleanDocument(document)
	words := strings.Split(cleaned, " ")
	wordCount = make(map[string]int)
	for _, word := range words {
		if _, ok := stopWords[word]; !ok {
			key := stem(strings.ToLower(word))
			wordCount[key]++
		}
	}
	return
}

func cleanDocument(text string) string {
	return cleaner.ReplaceAllString(text, "")
}

// stem a word using the Snowball algorithm
func stem(word string) string {
	stemmed, err := snowball.Stem(word, "english", true)
	if err == nil {
		return stemmed
	}
	// fmt.Println("Cannot stem word:", word)
	return word
}
