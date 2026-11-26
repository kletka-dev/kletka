use rand::RngExt;

const ADJECTIVES: &[&str] = &[
    "ace", "apt", "fit", "fun", "odd", "top", "able", "beau", "bold", "calm", "chic", "cool",
    "deep", "deft", "easy", "epic", "fair", "fine", "free", "full", "game", "glad", "glow", "good",
    "holy", "keen", "kind", "lean", "mild", "neat", "nice", "open", "pure", "real", "snug", "spry",
    "tidy", "true", "warm", "wavy", "wise", "adept", "agile", "alert", "alive", "ample", "angel",
    "awake", "aware", "brave", "brisk", "chill", "clean", "clear", "close", "comic", "eager",
    "elite", "first", "fleet", "fresh", "grace", "grand", "great", "happy", "hardy", "ideal",
    "jolly", "light", "lithe", "loyal", "lucid", "lucky", "lunar", "magic", "merry", "nifty",
    "noble", "peppy", "perky", "proud", "quick", "quiet", "ready", "regal", "savvy", "sharp",
    "smart", "solid", "sound", "sunny", "super", "sweet", "swift", "vivid", "witty", "zesty",
];

const SUBSTANTIVES: &[&str] = &[
    "ox", "aim", "air", "arm", "bud", "day", "hay", "jam", "jay", "joy", "key", "map", "may",
    "nod", "ore", "pen", "sky", "sun", "way", "zen", "ant", "ape", "auk", "bat", "bee", "cat",
    "cod", "cow", "dog", "elk", "fox", "hen", "owl", "pig", "ram", "rat", "yak", "boar", "buck",
    "bull", "calf", "carp", "crab", "crow", "deer", "dove", "fish", "foal", "frog", "goat", "gull",
    "hare", "hawk", "ibex", "kiwi", "kudu", "lamb", "lion", "lynx", "mink", "mole", "mule", "newt",
    "orca", "oryx", "puma", "seal", "slug", "stag", "swan", "tern", "toad", "tuna", "wasp", "wolf",
    "zebu", "bison", "camel", "crane", "eagle", "finch", "goose", "heron", "hippo", "horse",
    "hyena", "koala", "llama", "macaw", "moose", "otter", "quail", "raven", "robin", "shark",
    "sheep", "shrew", "skunk", "sloth", "snail", "squid", "tapir", "tiger", "trout", "whale",
    "zebra", "ally", "arch", "area", "aura", "axis", "bank", "barn", "beam", "bell", "belt",
    "bend", "bird", "boat", "bond", "book", "boot", "bowl", "brim", "calm", "camp", "card", "care",
    "cell", "city", "clan", "club", "code", "core", "crux", "dawn", "deal", "film", "firm", "flag",
    "flow", "foam", "gate", "gift", "glow", "hall", "hand", "harp", "hill", "home", "hope", "host",
    "idea", "isle", "item", "keel", "knot", "land", "leaf", "link", "lion", "loom", "love", "luck",
    "mark", "moon", "moss", "nook", "note", "pact", "page", "path", "peak", "poem", "port", "ring",
    "road", "rock", "roof", "rule", "sail", "seal", "seed", "song", "star", "tide", "tree", "tune",
    "walk", "ward", "wave", "well", "wind", "wing", "wish", "wood", "work", "zone", "amity",
    "asset", "bloom", "brook", "bunch", "charm", "chart", "cheer", "chord", "cliff", "cloud",
    "coast", "comet", "craft", "crane", "crest", "crowd", "crown", "cycle", "faith", "field",
    "flame", "fleet", "focus", "forge", "frame", "fruit", "glade", "grace", "grain", "grove",
    "guide", "guild", "haven", "heart", "honey", "honor", "humor", "image", "index", "jewel",
    "judge", "kudos", "lumen", "lunar", "magic", "march", "marsh", "mercy", "model", "moral",
    "music", "niche", "oasis", "ocean", "opera", "orbit", "order", "peace", "pearl", "petal",
    "phase", "piano", "pilot", "place", "plaza", "prism", "proof", "pulse", "quest", "quiet",
    "quill", "radar", "rally", "range", "realm", "reign", "river", "route", "scene", "scope",
    "score", "shade", "shape", "shore", "skill", "spark", "spice", "spire", "spoke", "stone",
    "story", "table", "token", "trend", "tribe", "trust", "unity", "valor", "value", "verse",
    "vista", "voice", "world",
];

pub fn generate_name() -> String {
    let mut rng = rand::rng();

    let prefix = ADJECTIVES[rng.random_range(0..ADJECTIVES.len())];
    let suffix = SUBSTANTIVES[rng.random_range(0..SUBSTANTIVES.len())];
    format!("{prefix}-{suffix}")
}
