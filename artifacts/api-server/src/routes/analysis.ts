import { isIP } from "node:net";
import { Router, type IRouter, type RequestHandler } from "express";
import {
  AnalyzeMessageBody,
  AnalyzeMessageResponse,
  AnalyzeUrlBody,
  AnalyzeUrlResponse,
} from "@workspace/api-zod";

type Language = "en" | "hi" | "te";
type RiskLevel = "low" | "medium" | "high";
type ScanKind = "url" | "message";

type IndicatorCopy = {
  title: Record<Language, string>;
  detail: Record<Language, string>;
};

type Rule = {
  code: string;
  weight: number;
};

const urlIndicatorCopy: Record<string, IndicatorCopy> = {
  ip_address: {
    title: { en: "IP address used as the website", hi: "वेबसाइट के लिए IP address का उपयोग", te: "వెబ్‌సైట్‌కు IP address ఉపయోగించారు" },
    detail: {
      en: "The address points to a numeric network address instead of a recognizable domain.",
      hi: "पते में पहचाने जाने वाले डोमेन के बजाय संख्यात्मक नेटवर्क पता है।",
      te: "గుర్తించగల డొమైన్‌కు బదులుగా సంఖ్యా నెట్‌వర్క్ చిరునామా ఉంది.",
    },
  },
  punycode: {
    title: { en: "Internationalized or encoded domain", hi: "एन्कोड किया गया डोमेन", te: "ఎన్‌కోడ్ చేసిన డొమైన్" },
    detail: {
      en: "The domain contains an encoded label that can sometimes resemble another site's name.",
      hi: "डोमेन में ऐसा एन्कोड किया गया भाग है जो कभी-कभी किसी दूसरी साइट जैसा दिख सकता है।",
      te: "డొమైన్‌లో వేరే సైట్‌లా కనిపించగల ఎన్‌కోడ్ చేసిన భాగం ఉంది.",
    },
  },
  user_info: {
    title: { en: "Extra sign-in-like text in the address", hi: "पते में अतिरिक्त साइन-इन जैसा टेक्स्ट", te: "చిరునామాలో అదనపు సైన్-ఇన్‌లాంటి టెక్స్ట్" },
    detail: {
      en: "Text before the @ symbol can make a link appear to belong to a different site.",
      hi: "@ चिन्ह से पहले का टेक्स्ट लिंक को किसी दूसरी साइट का दिखा सकता है।",
      te: "@ గుర్తుకు ముందు ఉన్న టెక్స్ట్ లింక్‌ను వేరే సైట్‌లా చూపవచ్చు.",
    },
  },
  lookalike_domain: {
    title: { en: "Possible lookalike domain", hi: "मिलते-जुलते डोमेन की संभावना", te: "పోలిన డొమైన్ ఉండే అవకాశం" },
    detail: {
      en: "The domain contains a spelling or brand-like pattern that can be confused with a familiar service.",
      hi: "डोमेन की वर्तनी या ब्रांड जैसा पैटर्न किसी परिचित सेवा से भ्रमित कर सकता है।",
      te: "డొమైన్ స్పెల్లింగ్ లేదా బ్రాండ్‌లాంటి నమూనా తెలిసిన సేవతో గందరగోళం కలిగించవచ్చు.",
    },
  },
  many_subdomains: {
    title: { en: "Several subdomains", hi: "कई सबडोमेन", te: "అనేక సబ్‌డొమైన్‌లు" },
    detail: {
      en: "The address has several labels before its main domain, so check which domain actually owns it.",
      hi: "मुख्य डोमेन से पहले पते में कई हिस्से हैं। देखें कि असली डोमेन किसका है।",
      te: "ప్రధాన డొమైన్‌కు ముందు అనేక భాగాలు ఉన్నాయి. అసలు డొమైన్ ఎవరిదో పరిశీలించండి.",
    },
  },
  url_shortener: {
    title: { en: "Link shortener hides the destination", hi: "लिंक शॉर्टनर गंतव्य छिपाता है", te: "లింక్ షార్టెనర్ గమ్యాన్ని దాచుతుంది" },
    detail: {
      en: "This shortened address does not reveal the final website in the text you provided.",
      hi: "आपके दिए गए छोटे पते में अंतिम वेबसाइट दिखाई नहीं देती।",
      te: "మీరు ఇచ్చిన చిన్న చిరునామాలో చివరి వెబ్‌సైట్ కనిపించదు.",
    },
  },
  no_https: {
    title: { en: "Connection is not marked secure", hi: "कनेक्शन सुरक्षित चिह्नित नहीं है", te: "కనెక్షన్ సురక్షితంగా గుర్తించబడలేదు" },
    detail: {
      en: "The link uses HTTP rather than HTTPS. This is only one signal and does not prove the site is harmful.",
      hi: "लिंक HTTPS के बजाय HTTP का उपयोग करता है। यह केवल एक संकेत है, नुकसान का प्रमाण नहीं।",
      te: "లింక్ HTTPS బదులుగా HTTP ఉపయోగిస్తోంది. ఇది ఒక సంకేతం మాత్రమే; హానికరమని నిరూపించదు.",
    },
  },
  long_url: {
    title: { en: "Unusually long address", hi: "असामान्य रूप से लंबा पता", te: "అసాధారణంగా పొడవైన చిరునామా" },
    detail: {
      en: "Long addresses can make it harder to notice the real destination or unexpected parts.",
      hi: "लंबे पते में असली गंतव्य या अनपेक्षित हिस्से पहचानना कठिन हो सकता है।",
      te: "పొడవైన చిరునామాలో అసలు గమ్యం లేదా అనుకోని భాగాలను గుర్తించడం కష్టమవుతుంది.",
    },
  },
  encoded_chars: {
    title: { en: "Encoded characters in the link", hi: "लिंक में एन्कोड किए गए अक्षर", te: "లింక్‌లో ఎన్‌కోడ్ చేసిన అక్షరాలు" },
    detail: {
      en: "The address includes encoded characters. They can be normal, but may also obscure what the link contains.",
      hi: "पते में एन्कोड किए गए अक्षर हैं। वे सामान्य भी हो सकते हैं, पर सामग्री छिपा सकते हैं।",
      te: "చిరునామాలో ఎన్‌కోడ్ చేసిన అక్షరాలున్నాయి. అవి సాధారణమైనవైనా, లింక్ వివరాలను దాచవచ్చు.",
    },
  },
  untrusted_tld: {
    title: { en: "Less familiar domain ending", hi: "कम परिचित डोमेन अंत", te: "తక్కువగా తెలిసిన డొమైన్ ముగింపు" },
    detail: {
      en: "This domain ending is often used in disposable links. Its presence alone does not prove abuse.",
      hi: "ऐसे डोमेन अंत अस्थायी लिंक में अधिक दिखते हैं। केवल इससे धोखाधड़ी सिद्ध नहीं होती।",
      te: "ఈ డొమైన్ ముగింపు తాత్కాలిక లింక్‌లలో తరచుగా కనిపిస్తుంది. ఇది ఒక్కటే మోసాన్ని నిరూపించదు.",
    },
  },
  nonstandard_port: {
    title: { en: "Unusual connection port", hi: "असामान्य कनेक्शन पोर्ट", te: "అసాధారణ కనెక్షన్ పోర్ట్" },
    detail: {
      en: "The address uses a less common network port. Most everyday websites do not need one.",
      hi: "पता कम उपयोग होने वाला नेटवर्क पोर्ट इस्तेमाल करता है। आम वेबसाइटों को प्रायः इसकी ज़रूरत नहीं होती।",
      te: "చిరునామా తక్కువగా ఉపయోగించే నెట్‌వర్క్ పోర్ట్‌ను వాడుతోంది. సాధారణ వెబ్‌సైట్‌లకు ఇది సాధారణంగా అవసరం లేదు.",
    },
  },
  suspicious_action: {
    title: { en: "Sensitive action suggested by the address", hi: "पते में संवेदनशील कार्रवाई का संकेत", te: "చిరునామా సున్నితమైన చర్యను సూచిస్తోంది" },
    detail: {
      en: "The address contains wording commonly used for sign-in, payment, or account verification.",
      hi: "पते में साइन-इन, भुगतान या खाता जाँच से जुड़े आम शब्द हैं।",
      te: "చిరునామాలో సైన్-ఇన్, చెల్లింపు లేదా ఖాతా నిర్ధారణకు సాధారణంగా వాడే పదాలున్నాయి.",
    },
  },
};

const messageIndicatorCopy: Record<string, IndicatorCopy> = {
  urgency: {
    title: { en: "Pressure to act immediately", hi: "तुरंत कार्रवाई का दबाव", te: "వెంటనే చర్య తీసుకోవాలని ఒత్తిడి" },
    detail: {
      en: "The message uses urgent language that may discourage you from checking it calmly.",
      hi: "संदेश में जल्दबाज़ी वाली भाषा है जो आपको शांत होकर जाँचने से रोक सकती है।",
      te: "సందేశం ప్రశాంతంగా పరిశీలించకుండా చేసే అత్యవసర భాషను ఉపయోగిస్తోంది.",
    },
  },
  credential_request: {
    title: { en: "Request for a password, OTP, or account details", hi: "पासवर्ड, OTP या खाते की जानकारी माँगी गई", te: "పాస్‌వర్డ్, OTP లేదా ఖాతా వివరాలు అడిగారు" },
    detail: {
      en: "A legitimate organization should not ask you to share an OTP or password through a message.",
      hi: "कोई वैध संस्था संदेश के ज़रिए आपका OTP या पासवर्ड नहीं माँगनी चाहिए।",
      te: "నిజమైన సంస్థ సందేశం ద్వారా మీ OTP లేదా పాస్‌వర్డ్ అడగకూడదు.",
    },
  },
  payment_request: {
    title: { en: "Unexpected payment request", hi: "अनपेक्षित भुगतान का अनुरोध", te: "అనుకోని చెల్లింపు అభ్యర్థన" },
    detail: {
      en: "The message asks for money or a fee. Verify through a contact method you already trust.",
      hi: "संदेश पैसे या शुल्क माँगता है। पहले से भरोसेमंद संपर्क माध्यम से जाँचें।",
      te: "సందేశం డబ్బు లేదా రుసుము అడుగుతోంది. మీకు ముందే తెలిసిన సంప్రదింపు మార్గంలో నిర్ధారించండి.",
    },
  },
  impersonation: {
    title: { en: "Organization or authority mentioned", hi: "संस्था या अधिकारी का उल्लेख", te: "సంస్థ లేదా అధికార ప్రస్తావన" },
    detail: {
      en: "The message refers to a bank, company, government body, or delivery service. The sender has not been verified.",
      hi: "संदेश बैंक, कंपनी, सरकारी विभाग या डिलीवरी सेवा का ज़िक्र करता है। भेजने वाले की पुष्टि नहीं हुई है।",
      te: "సందేశం బ్యాంక్, కంపెనీ, ప్రభుత్వ విభాగం లేదా డెలివరీ సేవను ప్రస్తావిస్తోంది. పంపినవారిని ధృవీకరించలేదు.",
    },
  },
  prize_claim: {
    title: { en: "Unexpected prize or reward", hi: "अनपेक्षित इनाम या पुरस्कार", te: "అనుకోని బహుమతి లేదా రివార్డ్" },
    detail: {
      en: "The message claims you won something unexpectedly. Be cautious if it asks for money or personal details.",
      hi: "संदेश अनपेक्षित जीत का दावा करता है। पैसे या निजी जानकारी माँगे तो सावधान रहें।",
      te: "సందేశం మీరు అనుకోకుండా గెలిచారని చెబుతోంది. డబ్బు లేదా వ్యక్తిగత వివరాలు అడిగితే జాగ్రత్త.",
    },
  },
  link_present: {
    title: { en: "Link included in the message", hi: "संदेश में लिंक शामिल है", te: "సందేశంలో లింక్ ఉంది" },
    detail: {
      en: "A link was found. Its destination was not opened or checked against a live threat database.",
      hi: "एक लिंक मिला। उसे खोला नहीं गया और लाइव खतरा डेटाबेस में जाँचा नहीं गया।",
      te: "ఒక లింక్ కనిపించింది. దాన్ని తెరవలేదు లేదా ప్రత్యక్ష ముప్పు డేటాబేస్‌లో తనిఖీ చేయలేదు.",
    },
  },
  unusual_contact: {
    title: { en: "Unusual reply or contact instructions", hi: "जवाब या संपर्क का असामान्य तरीका", te: "అసాధారణ ప్రత్యుత్తరం లేదా సంప్రదింపు సూచనలు" },
    detail: {
      en: "The message asks you to reply to an unfamiliar number, account, or channel.",
      hi: "संदेश आपसे किसी अपरिचित नंबर, खाते या चैनल पर जवाब माँगता है।",
      te: "తెలియని నంబర్, ఖాతా లేదా ఛానెల్‌కు సమాధానం ఇవ్వమని సందేశం అడుగుతోంది.",
    },
  },
};

const recommendations: Record<string, Record<Language, string>> = {
  verify: {
    en: "Contact the organization using its official app or a number you already trust.",
    hi: "संस्था से उसके आधिकारिक ऐप या पहले से भरोसेमंद नंबर से संपर्क करें।",
    te: "సంస్థ యొక్క అధికారిక యాప్ లేదా మీకు ముందే తెలిసిన నంబర్ ద్వారా సంప్రదించండి.",
  },
  do_not_share: {
    en: "Never share a password, one-time code, card PIN, or banking details in response to a message.",
    hi: "किसी संदेश के जवाब में पासवर्ड, OTP, कार्ड PIN या बैंक जानकारी साझा न करें।",
    te: "సందేశానికి ప్రతిస్పందనగా పాస్‌వర్డ్, OTP, కార్డ్ PIN లేదా బ్యాంక్ వివరాలు పంచుకోవద్దు.",
  },
  avoid_link: {
    en: "Do not open the link or download files unless you independently verify the sender and destination.",
    hi: "भेजने वाले और गंतव्य की अलग से पुष्टि किए बिना लिंक न खोलें और फ़ाइलें डाउनलोड न करें।",
    te: "పంపినవారిని, గమ్యాన్ని విడిగా నిర్ధారించకపోతే లింక్ తెరవకండి లేదా ఫైల్‌లు డౌన్‌లోడ్ చేయకండి.",
  },
  slow_down: {
    en: "Pause before acting. Scammers often use deadlines or fear to rush people.",
    hi: "कार्रवाई से पहले रुकें। धोखेबाज़ अक्सर समयसीमा या डर दिखाकर जल्दबाज़ी करवाते हैं।",
    te: "చర్యకు ముందు ఆగండి. మోసగాళ్లు తరచుగా గడువు లేదా భయంతో తొందరపెడతారు.",
  },
  check_domain: {
    en: "Read the domain from right to left and make sure the main domain is the one you expect.",
    hi: "डोमेन को दाएँ से बाएँ पढ़ें और मुख्य डोमेन की पुष्टि करें।",
    te: "డొమైన్‌ను కుడి నుంచి ఎడమకు చదివి, ప్రధాన డొమైన్ మీరు ఆశించినదేనో నిర్ధారించండి.",
  },
  low_caution: {
    en: "No strong pattern was found, but that does not prove the link or message is safe.",
    hi: "कोई मज़बूत संकेत नहीं मिला, लेकिन इससे लिंक या संदेश सुरक्षित सिद्ध नहीं होता।",
    te: "బలమైన సంకేతం కనిపించలేదు; అయినా లింక్ లేదా సందేశం సురక్షితమని దీని అర్థం కాదు.",
  },
};

const explanationCopy: Record<Language, Record<RiskLevel, string>> = {
  en: {
    low: "This rule-based check found few strong warning signs. It is not a safety guarantee, and no live threat database was checked.",
    medium: "This rule-based check found patterns worth checking before you act. It cannot confirm who sent this or whether it is malicious.",
    high: "This rule-based check found several concerning patterns. Treat the link or message with care; this is not a verified live threat report.",
  },
  hi: {
    low: "इस नियम-आधारित जाँच में कुछ ही मज़बूत चेतावनी संकेत मिले। यह सुरक्षा की गारंटी नहीं है और लाइव खतरा डेटाबेस नहीं जाँचा गया।",
    medium: "इस नियम-आधारित जाँच में कार्रवाई से पहले जाँचने योग्य संकेत मिले। यह पुष्टि नहीं कर सकती कि भेजने वाला कौन है या संदेश दुर्भावनापूर्ण है।",
    high: "इस नियम-आधारित जाँच में कई चिंताजनक संकेत मिले। लिंक या संदेश से सावधान रहें; यह सत्यापित लाइव खतरा रिपोर्ट नहीं है।",
  },
  te: {
    low: "ఈ నియమాధారిత తనిఖీలో కొన్ని బలమైన హెచ్చరిక సంకేతాలు మాత్రమే కనిపించాయి. ఇది భద్రతకు హామీ కాదు; ప్రత్యక్ష ముప్పు డేటాబేస్ తనిఖీ కాలేదు.",
    medium: "చర్యకు ముందు పరిశీలించాల్సిన నమూనాలు ఈ నియమాధారిత తనిఖీలో కనిపించాయి. పంపినవారిని లేదా ఇది హానికరమో నిర్ధారించలేము.",
    high: "ఈ నియమాధారిత తనిఖీలో అనేక ఆందోళనకర నమూనాలు కనిపించాయి. లింక్ లేదా సందేశంతో జాగ్రత్తగా ఉండండి; ఇది ధృవీకరించిన ప్రత్యక్ష ముప్పు నివేదిక కాదు.",
  },
};

const suspiciousTlds = new Set(["click", "country", "gq", "loan", "mov", "tk", "top", "work", "zip"]);
const shorteners = new Set([
  "bit.ly", "buff.ly", "is.gd", "lnkd.in", "rebrand.ly", "t.co", "tiny.cc", "tinyurl.com", "shorturl.at",
]);
const knownBrands = ["amazon", "apple", "facebook", "google", "instagram", "microsoft", "netflix", "paypal", "whatsapp"];
const urgencyPattern = /\b(urgent|immediately|act now|final warning|within \d+ (?:hours?|minutes?)|account (?:will be|is being) (?:blocked|suspended)|expires? today|verify now|तुरंत|अभी करें|खाता बंद|వెంటనే|ఇప్పుడే చేయండి)\b/i;
const credentialPattern = /\b(password|passcode|one[- ]time (?:password|code)|otp|pin number|card pin|cvv|cvc|banking (?:details|information)|login (?:details|credentials)|share (?:your )?(?:code|otp)|पासवर्ड|ओटीपी|बैंक विवरण|పాస్‌వర్డ్|ఓటీపీ|బ్యాంక్ వివరాలు)\b/i;
const paymentPattern = /\b(pay|payment|transfer|send (?:money|₹|rs\.?|inr)|processing fee|release fee|customs fee|refund fee|claim fee|pay now|₹\s?\d+|rs\.?\s?\d+|inr\s?\d+|भुगतान|शुल्क|पैसे भेजें|చెల్లింపు|రుసుము|డబ్బు పంపండి)\b/i;
const impersonationPattern = /\b(bank|government|police|tax department|income tax|support team|customer care|delivery|courier|electricity board|aadhaar|uidai|sbi|hdfc|icici|rbi|बैंक|सरकार|पुलिस|आयकर|डिलीवरी|ఆర్బీఐ|ప్రభుత్వం|బ్యాంక్)\b/i;
const prizePattern = /\b(you (?:have )?won|winner|prize|lottery|reward|claim your|selected (?:as|for)|free gift|इनाम|पुरस्कार|लॉटरी|బహుమతి|గెలిచారు|రివార్డ్)\b/i;
const urlPattern = /(?:https?:\/\/|www\.)\S+/i;
const unusualContactPattern = /\b(reply|respond|whatsapp|telegram|text us|call this number|contact only|dm us|direct message)\b.{0,50}\b(?:number|account|link|whatsapp|telegram|below|here)\b|\b(whatsapp|telegram|dm|direct message)\b/i;

const rateBuckets = new Map<string, { start: number; count: number }>();

const analysisRateLimit: RequestHandler = (req, res, next) => {
  const now = Date.now();
  const key = req.ip || "unknown";
  const current = rateBuckets.get(key);
  if (!current || now - current.start >= 60_000) {
    rateBuckets.set(key, { start: now, count: 1 });
    if (rateBuckets.size > 2_000) {
      for (const [bucketKey, bucket] of rateBuckets) {
        if (now - bucket.start >= 60_000) rateBuckets.delete(bucketKey);
      }
    }
    next();
    return;
  }
  if (current.count >= 30) {
    res.setHeader("Retry-After", String(Math.max(1, Math.ceil((60_000 - (now - current.start)) / 1_000))));
    res.status(429).json({ error: "Scan limit reached. Please wait a moment before trying again." });
    return;
  }
  current.count += 1;
  next();
};

function getRiskLevel(score: number): RiskLevel {
  if (score >= 65) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function toIndicators(rules: Rule[], copy: Record<string, IndicatorCopy>, language: Language) {
  return rules.map(({ code }) => {
    const text = copy[code];
    return { code, title: text.title[language], detail: text.detail[language] };
  });
}

function levenshtein(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    let previous = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const old = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1));
      previous = old;
    }
  }
  return row[b.length];
}

function urlRules(rawValue: string): Rule[] {
  const trimmed = rawValue.trim();
  const normalized = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("Enter a valid web address, such as example.com.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS web addresses can be analyzed.");
  }
  if (!parsed.hostname) throw new Error("Enter a valid web address with a domain name.");

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const labels = host.split(".");
  const rootLabel = labels.length > 1 ? labels[labels.length - 2] : labels[0];
  const rootDomain = labels.slice(-2).join(".");
  const rules: Rule[] = [];
  const add = (code: string, weight: number) => {
    if (!rules.some((rule) => rule.code === code)) rules.push({ code, weight });
  };

  if (isIP(host)) add("ip_address", 45);
  if (host.includes("xn--")) add("punycode", 45);
  if (parsed.username || parsed.password) add("user_info", 50);

  const subdomains = labels.length - 2;
  if (subdomains >= 3) add("many_subdomains", 20);
  const subdomainText = labels.slice(0, -2).join(".");
  if (knownBrands.some((brand) => subdomainText.includes(brand))) add("lookalike_domain", 35);
  const rootTokens = rootLabel.split(/[-_.]/);
  if (knownBrands.some((brand) => rootTokens.some((token) => token !== brand && token.length >= 5 && levenshtein(token, brand) <= 2))) {
    add("lookalike_domain", 35);
  }
  const tld = labels.at(-1) ?? "";
  if (suspiciousTlds.has(tld)) add("untrusted_tld", 20);
  if (shorteners.has(rootDomain)) add("url_shortener", 20);
  if (parsed.protocol === "http:") add("no_https", 15);
  if (trimmed.length > 120) add("long_url", 15);
  if (/%[0-9a-f]{2}/i.test(trimmed)) add("encoded_chars", 15);
  if (parsed.port && !["80", "443"].includes(parsed.port)) add("nonstandard_port", 25);
  if (/(?:login|signin|verify|secure|payment|update-account|reset-password)/i.test(`${host}${parsed.pathname}`)) {
    add("suspicious_action", 15);
  }
  return rules;
}

function messageRules(message: string): Rule[] {
  const rules: Rule[] = [];
  const add = (code: string, weight: number) => rules.push({ code, weight });
  if (urgencyPattern.test(message)) add("urgency", 20);
  if (credentialPattern.test(message)) add("credential_request", 45);
  if (paymentPattern.test(message)) add("payment_request", 30);
  if (impersonationPattern.test(message)) add("impersonation", 25);
  if (prizePattern.test(message)) add("prize_claim", 30);
  if (urlPattern.test(message)) add("link_present", 15);
  if (unusualContactPattern.test(message)) add("unusual_contact", 15);
  return rules;
}

function getRecommendations(kind: ScanKind, rules: Rule[], riskLevel: RiskLevel, language: Language): string[] {
  const codes = new Set(rules.map((rule) => rule.code));
  const result: string[] = [];
  const add = (key: string) => {
    const text = recommendations[key][language];
    if (!result.includes(text)) result.push(text);
  };
  if (riskLevel === "high") add("avoid_link");
  if (riskLevel !== "low" || codes.has("impersonation") || codes.has("payment_request") || codes.has("prize_claim")) add("verify");
  if (codes.has("credential_request")) add("do_not_share");
  if (codes.has("urgency")) add("slow_down");
  if (kind === "url" && (codes.has("lookalike_domain") || codes.has("many_subdomains") || codes.has("url_shortener"))) add("check_domain");
  if (riskLevel === "low") add("low_caution");
  return result;
}

function createAssessment(kind: ScanKind, rules: Rule[], language: Language, copy: Record<string, IndicatorCopy>) {
  const riskScore = Math.min(100, rules.reduce((total, rule) => total + rule.weight, 0));
  const riskLevel = getRiskLevel(riskScore);
  const assessment = {
    id: crypto.randomUUID(),
    kind,
    riskLevel,
    riskScore,
    indicators: toIndicators(rules, copy, language),
    recommendations: getRecommendations(kind, rules, riskLevel, language),
    explanation: explanationCopy[language][riskLevel],
    engine: "rule-based" as const,
    evaluatedAt: new Date().toISOString(),
    language,
  };
  return assessment;
}

function localizedLanguage(value: unknown): Language {
  return value === "hi" || value === "te" ? value : "en";
}

const router: IRouter = Router();

router.post("/analyze/url", analysisRateLimit, (req, res) => {
  const parsed = AnalyzeUrlBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Enter a web address no longer than 4,096 characters." });
    return;
  }
  try {
    const rules = urlRules(parsed.data.url);
    const result = AnalyzeUrlResponse.parse(
      createAssessment("url", rules, localizedLanguage(parsed.data.language), urlIndicatorCopy),
    );
    res.json(result);
  } catch (error) {
    res.status(400).json({
      error: error instanceof Error ? error.message : "Unable to analyze this address.",
    });
  }
});

router.post("/analyze/message", analysisRateLimit, (req, res) => {
  const parsed = AnalyzeMessageBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Enter a message no longer than 10,000 characters." });
    return;
  }
  const language = localizedLanguage(parsed.data.language);
  const result = AnalyzeMessageResponse.parse(
    createAssessment("message", messageRules(parsed.data.message), language, messageIndicatorCopy),
  );
  res.json(result);
});

export default router;
