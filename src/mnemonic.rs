use crate::{errors::Bip39Error, pbkdf2::pbkdf2, rng::Rng, utils::is_invalid_word_count};
use core::fmt;
use sha2::{Digest, Sha256};

pub const MIN_NB_WORDS: usize = 12;
pub const MAX_NB_WORDS: usize = 33;
pub const MAX_ENTROPY_BYTES: usize = 32;
pub const MAX_WORDS_DICT: usize = 2048;
pub const PBKDF2_ROUNDS: u32 = 2048;
pub const SEED_BYTE_LEN: usize = 64;

const EOF: u16 = u16::max_value();

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Mnemonic<'a> {
    lang_words: &'a [&'a str; MAX_WORDS_DICT],
    indicators: [u16; MAX_NB_WORDS],
    pub word_count: usize,
}

#[derive(Clone)]
pub struct MnemonicIter<'a, 'b> {
    mnemonic: &'b Mnemonic<'a>,
    position: usize,
}

#[derive(Clone)]
pub struct EntropyIter<'a> {
    mnemonic: &'a Mnemonic<'a>,
    word_idx: usize,
    bits: u32,
    bit_count: u32,
    bytes_produced: usize,
    bytes_to_produce: usize,
}

impl<'a> Iterator for EntropyIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes_produced >= self.bytes_to_produce {
            return None;
        }

        while self.bit_count < 8 {
            if self.word_idx >= self.mnemonic.word_count {
                return None;
            }

            let index = self.mnemonic.indicators[self.word_idx];

            self.bits = (self.bits << 11) | u32::from(index);
            self.bit_count += 11;
            self.word_idx += 1;
        }

        let shift = self.bit_count - 8;
        let byte = (self.bits >> shift) as u8;

        self.bit_count -= 8;
        self.bits &= (1 << self.bit_count) - 1;

        self.bytes_produced += 1;

        Some(byte)
    }
}

impl<'a, 'b> Iterator for MnemonicIter<'a, 'b> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.mnemonic.word_count {
            return None;
        }
        let word_index = self.mnemonic.indicators[self.position] as usize;
        self.position += 1;
        Some(self.mnemonic.lang_words[word_index])
    }
}

impl<'a> fmt::Display for Mnemonic<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, word) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            f.write_str(word)?;
        }
        Ok(())
    }
}

impl<'a> Mnemonic<'a> {
    pub fn from(dictionary: &'a [&'a str; MAX_WORDS_DICT]) -> Self {
        Self {
            lang_words: dictionary,
            indicators: [EOF; MAX_NB_WORDS],
            word_count: 0,
        }
    }

    pub fn iter<'b>(&'b self) -> MnemonicIter<'a, 'b> {
        MnemonicIter {
            mnemonic: self,
            position: 0,
        }
    }

    pub fn to_seed(&self, passphrase: &str) -> Result<[u8; SEED_BYTE_LEN], Bip39Error> {
        pbkdf2(self.iter(), passphrase.as_bytes(), PBKDF2_ROUNDS)
    }

    pub fn parse_str(
        lang_words: &'a [&'a str; MAX_WORDS_DICT],
        s: &str,
    ) -> Result<Self, Bip39Error> {
        const MAX_TOTAL_BITS: usize = MAX_NB_WORDS * 11;
        const MAX_ENTROPY_BYTES: usize = 256 / 8;

        let mut temp_words = [""; MAX_NB_WORDS + 1];
        let mut word_count = 0;
        for word in s.split_whitespace() {
            if word_count >= temp_words.len() {
                word_count += 1;
                break;
            }
            temp_words[word_count] = word;
            word_count += 1;
        }

        if is_invalid_word_count(word_count) {
            return Err(Bip39Error::BadWordCount(word_count));
        }

        let total_bits = word_count * 11;
        let checksum_len_bits = word_count / 3;
        let entropy_len_bits = total_bits - checksum_len_bits;
        let entropy_len_bytes = entropy_len_bits / 8;

        let mut indicators = [EOF; MAX_NB_WORDS];
        let mut bits = [false; MAX_TOTAL_BITS];

        for i in 0..word_count {
            let word_str = temp_words[i];
            match lang_words.iter().position(|&w| w == word_str) {
                Some(idx) => {
                    let idx_u16 = idx as u16;
                    indicators[i] = idx_u16;
                    for j in 0..11 {
                        bits[i * 11 + j] = (idx_u16 >> (10 - j)) & 1 == 1;
                    }
                }
                None => return Err(Bip39Error::UnknownWord(i)),
            }
        }

        let mut entropy = [0u8; MAX_ENTROPY_BYTES];
        for i in 0..entropy_len_bytes {
            for j in 0..8 {
                if bits[i * 8 + j] {
                    entropy[i] |= 1 << (7 - j);
                }
            }
        }

        let hash = Sha256::digest(&entropy[0..entropy_len_bytes]);
        let mnemonic_checksum_bits = &bits[entropy_len_bits..total_bits];

        for i in 0..checksum_len_bits {
            let expected_bit = (hash[i / 8] >> (7 - (i % 8))) & 1 == 1;
            if mnemonic_checksum_bits[i] != expected_bit {
                return Err(Bip39Error::InvalidChecksum);
            }
        }

        Ok(Mnemonic {
            lang_words,
            indicators,
            word_count,
        })
    }

    pub fn to_entropy(&'a self) -> EntropyIter<'a> {
        let entropy_bytes_len = (self.word_count / 3) * 4;
        EntropyIter {
            mnemonic: self,
            word_idx: 0,
            bits: 0,
            bit_count: 0,
            bytes_produced: 0,
            bytes_to_produce: entropy_bytes_len,
        }
    }

    pub fn from_entropy(
        lang_words: &'a [&'a str; MAX_WORDS_DICT],
        entropy: &[u8],
    ) -> Result<Self, Bip39Error> {
        const MAX_ENTROPY_BITS: usize = 256;
        const MIN_ENTROPY_BITS: usize = 128;
        const MAX_CHECKSUM_BITS: usize = 8;

        let nb_bytes = entropy.len();
        let nb_bits = nb_bytes * 8;

        if nb_bits % 32 != 0 {
            return Err(Bip39Error::BadEntropyBitCount(nb_bits));
        }
        if nb_bits < MIN_ENTROPY_BITS || nb_bits > MAX_ENTROPY_BITS {
            return Err(Bip39Error::BadEntropyBitCount(nb_bits));
        }

        let check = Sha256::digest(entropy);
        let cs_bits = nb_bits / 32;

        let mut bits = [false; MAX_ENTROPY_BITS + MAX_CHECKSUM_BITS];

        for i in 0..nb_bytes {
            for j in 0..8 {
                bits[i * 8 + j] = (entropy[i] & (1 << (7 - j))) != 0;
            }
        }

        for i in 0..cs_bits {
            bits[nb_bits + i] = (check[i / 8] & (1 << (7 - (i % 8)))) > 0;
        }

        let total_bits = nb_bits + cs_bits;
        let word_count = total_bits / 11;

        let mut indicators = [EOF; MAX_NB_WORDS];
        for i in 0..word_count {
            let mut idx = 0u16;
            for j in 0..11 {
                if bits[i * 11 + j] {
                    idx += 1 << (10 - j);
                }
            }
            indicators[i] = idx;
        }

        Ok(Mnemonic {
            lang_words,
            indicators,
            word_count,
        })
    }

    pub fn generate<R: Rng>(
        rng: &mut R,
        lang_words: &'a [&'a str; MAX_WORDS_DICT],
        word_count: usize,
    ) -> Result<Self, Bip39Error> {
        if is_invalid_word_count(word_count) {
            return Err(Bip39Error::BadWordCount(word_count));
        }

        let entropy_bytes = (word_count / 3) * 4;
        let mut entropy = [0u8; (MAX_NB_WORDS / 3) * 4];

        Rng::fill_bytes(rng, &mut entropy[0..entropy_bytes]);

        let indicators = [0u16; MAX_NB_WORDS];

        Ok(Mnemonic {
            lang_words,
            indicators,
            word_count,
        })
    }

    pub fn checksum(&self) -> u8 {
        let last_word = self.indicators[self.word_count - 1];
        let mask = 0xFF >> (8 - self.word_count / 3);
        last_word as u8 & mask
    }
}

#[cfg(test)]
mod tests_mnemonic {
    use super::*;

    const EN_WORDS: [&str; 2048] = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
        "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add",
        "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair",
        "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport",
        "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost",
        "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
        "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal",
        "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any",
        "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area",
        "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive",
        "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
        "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract",
        "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
        "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby",
        "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
        "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle",
        "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave",
        "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
        "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth",
        "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind",
        "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil",
        "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom",
        "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze",
        "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
        "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build",
        "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
        "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus",
        "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy",
        "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon",
        "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual",
        "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave",
        "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
        "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check",
        "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice",
        "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen",
        "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever",
        "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth",
        "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
        "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
        "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress",
        "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral",
        "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course",
        "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash",
        "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime",
        "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise",
        "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard",
        "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
        "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal",
        "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease",
        "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise",
        "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive",
        "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect",
        "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel",
        "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt",
        "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance",
        "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin",
        "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon",
        "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive",
        "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf",
        "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
        "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either",
        "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite",
        "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty",
        "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage",
        "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter",
        "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode",
        "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics",
        "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite",
        "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
        "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra",
        "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false",
        "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal",
        "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed",
        "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction",
        "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish",
        "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame",
        "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower",
        "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot",
        "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster",
        "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog",
        "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury",
        "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage",
        "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general",
        "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
        "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide",
        "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold",
        "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain",
        "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery",
        "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym",
        "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh",
        "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog",
        "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint",
        "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home",
        "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour",
        "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle",
        "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore",
        "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose",
        "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate",
        "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial",
        "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect",
        "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite",
        "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar",
        "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey",
        "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen",
        "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit",
        "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label",
        "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin",
        "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf",
        "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend",
        "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library",
        "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid",
        "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic",
        "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage",
        "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
        "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango",
        "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage",
        "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum",
        "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody",
        "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh",
        "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
        "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix",
        "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey",
        "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion",
        "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply",
        "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth",
        "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need",
        "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
        "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal",
        "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear",
        "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe",
        "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office",
        "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion",
        "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
        "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
        "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner",
        "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda",
        "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party",
        "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment",
        "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people",
        "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
        "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer",
        "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play",
        "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole",
        "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post",
        "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict",
        "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print",
        "priority", "prison", "private", "prize", "problem", "process", "produce", "profit",
        "program", "project", "promote", "proof", "property", "prosper", "protect", "proud",
        "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
        "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid",
        "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit",
        "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp",
        "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor",
        "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record",
        "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular",
        "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
        "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require",
        "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat",
        "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice",
        "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk",
        "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance",
        "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber",
        "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe",
        "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy",
        "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene",
        "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen",
        "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section",
        "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense",
        "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
        "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship",
        "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp",
        "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent",
        "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister",
        "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull",
        "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot",
        "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap",
        "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier",
        "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound",
        "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
        "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
        "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square",
        "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand",
        "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still",
        "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
        "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
        "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit",
        "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface",
        "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp",
        "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol",
        "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank",
        "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten",
        "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then",
        "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb",
        "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired",
        "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet",
        "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top",
        "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward",
        "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap",
        "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger",
        "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth",
        "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve",
        "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable",
        "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform",
        "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update",
        "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used",
        "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley",
        "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet",
        "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran",
        "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin",
        "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void",
        "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut",
        "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way",
        "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird",
        "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip",
        "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing",
        "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
        "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck",
        "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth",
        "zebra", "zero", "zone", "zoo",
    ];

    #[test]
    fn test_from_entropy_valid_128_bits() {
        let entropy = [0u8; 16];
        let mnemonic = Mnemonic::from_entropy(&EN_WORDS, &entropy).unwrap();

        assert_eq!(mnemonic.word_count, 12);

        let expected_words = [
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "about",
        ];

        let mut mnemonic_iter = mnemonic.iter();
        let mut expected_iter = expected_words.iter();

        for _ in 0..expected_words.len() {
            assert_eq!(mnemonic_iter.next(), expected_iter.next().copied());
        }

        assert_eq!(mnemonic_iter.next(), None);
        assert_eq!(expected_iter.next(), None);
    }

    #[test]
    fn test_from_entropy_valid_256_bits() {
        let entropy = [0u8; 32];
        let mnemonic = Mnemonic::from_entropy(&EN_WORDS, &entropy).unwrap();
        assert_eq!(mnemonic.word_count, 24);
    }

    #[test]
    fn test_from_entropy_invalid_length() {
        let entropy = [0u8; 17];
        let result = Mnemonic::from_entropy(&EN_WORDS, &entropy);
        assert_eq!(result, Err(Bip39Error::BadEntropyBitCount(136)));
    }

    #[test]
    fn test_from_entropy_too_short() {
        let entropy = [0u8; 4];
        let result = Mnemonic::from_entropy(&EN_WORDS, &entropy);
        assert_eq!(result, Err(Bip39Error::BadEntropyBitCount(32)));
    }

    #[test]
    fn test_from_entropy_too_long() {
        let entropy = [0u8; 36];
        let result = Mnemonic::from_entropy(&EN_WORDS, &entropy);
        assert_eq!(result, Err(Bip39Error::BadEntropyBitCount(288)));
    }

    #[test]
    fn test_checksum() {
        let vectors = [
            "00000000000000000000000000000000",
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "80808080808080808080808080808080",
            "ffffffffffffffffffffffffffffffff",
            "000000000000000000000000000000000000000000000000",
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "808080808080808080808080808080808080808080808080",
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "8080808080808080808080808080808080808080808080808080808080808080",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "9e885d952ad362caeb4efe34a8e91bd2",
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "23db8160a31d3e0dca3688ed941adbf3",
            "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "f30f8c1da665478f49b001d94c5fc452",
            "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "ed3b83f0d7913a19667a1cfd7298cd57",
            "70639a4e81b151277b345476d169a3743ff3c141",
            "ba2520298b92063a7a0ee1d453ba92513af81d4f86e1d336",
            "9447d2cf44349cd88a58f5b4ff6f83b9a2d54c42f033e12b8e4d00cc",
            "38711e550dc6557df8082b2a87f7860ebbe47ea5867a7068f5f0f5b85db68be8",
        ];

        for entropy_hex in &vectors {
            let ent = hex::decode(entropy_hex).unwrap();
            let m = Mnemonic::from_entropy(&EN_WORDS, &ent).unwrap();
            let word_count = m.word_count;
            let cs = m.checksum();
            let digest = Sha256::digest(&ent);
            assert_eq!(digest[0] >> (8 - (word_count / 3)), cs);
        }
    }

    #[test]
    fn test_invalid_engish() {
        assert_eq!(
            Mnemonic::parse_str(
                &EN_WORDS,
                "getter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            ),
            Err(Bip39Error::UnknownWord(0))
        );

        assert_eq!(
            Mnemonic::parse_str(
                &EN_WORDS,
                "letter advice cagex absurd amount doctor acoustic avoid letter advice cage above",
            ),
            Err(Bip39Error::UnknownWord(2))
        );

        assert_eq!(
            Mnemonic::parse_str(
                &EN_WORDS,
                "advice cage absurd amount doctor acoustic avoid letter advice cage above",
            ),
            Err(Bip39Error::BadWordCount(11))
        );

        assert_eq!(
            Mnemonic::parse_str(
                &EN_WORDS,
                "primary advice cage absurd amount doctor acoustic avoid letter advice cage above",
            ),
            Err(Bip39Error::InvalidChecksum)
        );
    }

    #[test]
    fn test_vectors_english() {
        let test_vectors = [
			(
				"00000000000000000000000000000000",
				"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
				"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
			),
			(
				"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
				"legal winner thank year wave sausage worth useful legal winner thank yellow",
				"2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
			),
			(
				"80808080808080808080808080808080",
				"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
				"d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
			),
			(
				"ffffffffffffffffffffffffffffffff",
				"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
				"ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
			),
			(
				"000000000000000000000000000000000000000000000000",
				"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
				"035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
			),
			(
				"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
				"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
				"f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
			),
			(
				"808080808080808080808080808080808080808080808080",
				"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
				"107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
			),
			(
				"ffffffffffffffffffffffffffffffffffffffffffffffff",
				"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
				"0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
			),
			(
				"0000000000000000000000000000000000000000000000000000000000000000",
				"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
				"bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
			),
			(
				"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
				"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
				"bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
			),
			(
				"8080808080808080808080808080808080808080808080808080808080808080",
				"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
				"c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
			),
			(
				"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
				"dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
			),
			(
				"9e885d952ad362caeb4efe34a8e91bd2",
				"ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
				"274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
			),
			(
				"6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
				"gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
				"628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
			),
			(
				"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
				"hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
				"64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
			),
			(
				"c0ba5a8e914111210f2bd131f3d5e08d",
				"scheme spot photo card baby mountain device kick cradle pact join borrow",
				"ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
			),
			(
				"6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
				"horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
				"fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
			),
			(
				"9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
				"panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
				"72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
			),
			(
				"23db8160a31d3e0dca3688ed941adbf3",
				"cat swing flag economy stadium alone churn speed unique patch report train",
				"deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
			),
			(
				"8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
				"light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
				"4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
			),
			(
				"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
				"all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
				"26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
			),
			(
				"f30f8c1da665478f49b001d94c5fc452",
				"vessel ladder alter error federal sibling chat ability sun glass valve picture",
				"2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
			),
			(
				"c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
				"scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
				"7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
			),
			(
				"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
				"void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
				"01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
			)
		];

        for vector in &test_vectors {
            let entropy = hex::decode(&vector.0).unwrap();
            let mnemonic_str = vector.1;
            let seed = hex::decode(&vector.2).unwrap();
            let mnemonic = Mnemonic::from_entropy(&EN_WORDS, &entropy).unwrap();

            assert_eq!(
                mnemonic,
                Mnemonic::parse_str(&EN_WORDS, mnemonic_str).unwrap(),
                "failed vector: {}",
                mnemonic_str
            );
            assert_eq!(
                &seed[..],
                &mnemonic.to_seed("TREZOR").unwrap()[..],
                "failed vector: {}",
                mnemonic_str
            );

            {
                assert_eq!(
                    &mnemonic.to_string(),
                    mnemonic_str,
                    "failed vector: {}",
                    mnemonic_str
                );
                assert_eq!(
                    mnemonic,
                    Mnemonic::parse_str(&EN_WORDS, mnemonic_str).unwrap(),
                    "failed vector: {}",
                    mnemonic_str
                );
                assert_eq!(
                    mnemonic,
                    Mnemonic::parse_str(&EN_WORDS, mnemonic_str).unwrap(),
                    "failed vector: {}",
                    mnemonic_str
                );
                assert_eq!(
                    &seed[..],
                    &mnemonic.to_seed("TREZOR").unwrap()[..],
                    "failed vector: {}",
                    mnemonic_str
                );
                assert_eq!(
                    &entropy,
                    &mnemonic.to_entropy().into_iter().collect::<Vec<u8>>(),
                    "failed vector: {}",
                    mnemonic_str
                );
            }
        }
    }
}
