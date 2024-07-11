import os
import re


class FilePathCheck:
    def __init__(self, file_path):
        self.file_path = file_path
        self.tmp_lst = file_path.split(os.sep)
        self.origin_package_name = self.tmp_lst[1]

    def check_shared_and_pref(self):
        pattern_shared = re.compile(r'shared', re.IGNORECASE)
        pattern_pref = re.compile(r'pref', re.IGNORECASE)
        return pattern_shared in self.file_path and pattern_pref in self.file_path
        # return 'shared' in self.file_path and 'pref' in self.file_path

    def validate(self):
        if self.check_shared_and_pref():
            return self.file_path
        return None


class string_list:
    analysis_regex = {
        r"//s3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9._-]+",  # AWS Access Key ID
        r"//s3\.amazonaws\.com/[a-z0-9._-]+",  # AWS S3 Bucket
        r"[a-z0-9.-]+\.s3-[a-z0-9-]\.amazonaws\.com",
        r"[a-z0-9.-]+\.s3-website[.-](eu|ap|us|ca|sa|cn)",
        r"[a-z0-9.-]+\.s3\.amazonaws\.com",
        r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        r"(?:\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}",
        r"bearer\s[a-zA-Z0-9_\-:\.=]+",  # https://developer.twitter.com/en/docs/authentication/oauth-2-0/bearer-tokens 에 따라 개발자를 위한 것이므로 제3자에게 공개되어서는 안 됩니다.
        r"AKIA[0-9A-Z]{16}",
        r"(?<=://)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+",
        r"cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+",
        r"((?:N|M|O)[a-zA-Z0-9]{23}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27})$",
        r"EAACEdEose0cBA[0-9A-Za-z]+",
        r"facebook(.{0,20})?['\"][0-9]{13,17}",
        r"facebook.*['|\"][0-9a-f]{32}['|\"]",
        r"(facebook)(.{0,20})?['\"][0-9a-f]{32}",
        r"[a-z0-9.-]+\.firebaseio\.com",
        r"github.*['|\"][0-9a-zA-Z]{35,40}['|\"]",
        r"([a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*)$",
        r"AIza[0-9A-Za-z\-_]{35}",
        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        r"\"type\": \"service_account\"",
        r"ya29\.[0-9A-Za-z\-_]+",
        r"heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        r"(?i)^((?=.*[a-z])(?=.*[0-9])(?:[a-z0-9_=]+\.){2}(?:[a-z0-9_\-\+/=]*))$",
        r"(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\.]){2}[0-9A-Fa-f]{4})$",
        r"[0-9a-f]{32}-us[0-9]{1,2}",
        r"key-[0-9a-zA-Z]{32}",
        r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+",
        r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}[\"'\s]",
        r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        r"sk_live_[0-9a-z]{32}",
        r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
        r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        r"sq0atp-[0-9A-Za-z\-_]{22}",
        r"sq0csp-[0-9A-Za-z\-_]{43}",
        r"sk_live_[0-9a-zA-Z]{24}",
        r"rk_live_[0-9a-zA-Z]{24}",
        r"SK[0-9a-fA-F]{32}",
        r"twiter.*[1-9][0-9]+-[0-9a-zA-Z]{40}",  # https://developer.twitter.com/en/docs/authentication/oauth-2-0/bearer-tokens 에 따라 개발자를 위한 것이므로 제3자에게 공개되어서는 안 됩니다.
        r"twiter(.{0,20})?['\"][0-9a-z]{18,25}",
        r"twiter(.{0,20})?['\"][0-9a-z]{35,44}",
        r"\.child\(",
    }
