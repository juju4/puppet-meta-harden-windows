# https://forge.puppet.com/puppetlabs/iis
# https://puppet.com/blog/deploying-iis-and-aspnet-puppet
# https://www.metaltoad.com/blog/managing-iis-configuration-puppet-powershell-dsc

$iis_features = ['Web-WebServer','Web-Scripting-Tools', 'Web-Http-Errors', 'Web-Http-Logging', 'Web-Filtering']
#$iis_features = ['Web-WebServer','Web-Scripting-Tools', 'Web-Http-Errors', 'Web-Http-Logging', 'Web-Filtering', 'Web-Asp-Net45', 'NET-Framework-45-ASPNET']
$cert_fqdn = 'test.contoso.com'
# Recommended to move those to dedicated partition
$webroot = 'c:\\inetpub\\complete'
$logpath = 'c:\\inetpub\\logs\LogFiles'

iis_feature { $iis_features:
  ensure => 'present',
  include_management_tools => true,
  include_all_subfeatures => false,
}

# https://blogs.technet.microsoft.com/srd/2012/07/26/announcing-the-availability-of-modsecurity-extension-for-iis/
# https://azure.microsoft.com/en-us/blog/modsecurity-for-azure-websites/
$chocolatey_packages_iis = ['modsecurity' ]
$chocolatey_packages_iis.each |String $pkg| {
  package { "${pkg}":
    ensure   => latest,
    provider => chocolatey,
#    source   => 'https://<internal_repo>/chocolatey',
  }
}

# Delete the default website to prevent a port binding conflict.
iis_site {'Default Web Site':
  ensure  => absent,
  require => Iis_feature['Web-WebServer'],
}

# Create self-signed certificate
# for internet-facing system: https://letsencrypt.org/docs/client-options/, https://chocolatey.org/packages/letsencrypt-win-simple
exec { 'self-signed-certificate':
  command   => "New-SelfSignedCertificate -DnsName ${cert_fqdn} -CertStoreLocation cert:\\LocalMachine\\My",
  unless    => "if (Get-ChildItem -Path cert:\\LocalMachine\\My -Recurse -DNSName \"${cert_fqdn}\") { exit 1 }",
  provider  => powershell,
}
exec { 'self-signed-certificate-to-facts':
  command   => "(Get-ChildItem -Path cert:\\LocalMachine\\My -Recurse -DNSName \"${cert_fqdn}\" | Fl -property Thumbprint | Out-string).trim().Replace('Thumbprint : ', 'webserver_certhash=') | Out-File -Encoding ASCII C:\\ProgramData\\PuppetLabs\\facter\\facts.d\\webserver_certhash.txt",
  unless    => "if (Test-Path -Path \"C:\\ProgramData\\PuppetLabs\\facter\\facts.d\\webserver_certhash.txt\") { exit 1 }",
  provider  => powershell,
}

# Create User/Group
group { 'IISCompleteGroup':
   ensure => present,
}

# Create Directories

file { "${webroot}":
  ensure => 'directory'
}

file { 'c:\\inetpub\\complete_vdir':
  ensure => 'directory'
}

# Set Permissions

acl { "${webroot}":
  permissions => [
    {'identity' => 'IISCompleteGroup', 'rights' => ['read', 'execute']},
  ],
}

acl { 'c:\\inetpub\\complete_vdir':
  permissions => [
    {'identity' => 'IISCompleteGroup', 'rights' => ['read', 'execute']},
  ],
}

file { "${webroot}\\index.html":
  content => "<!DOCTYPE html>
<html>
  <head>
    <title>Default Root page</title>
  </head>
  <body>
    <h1>Welcome! web server is configured and active. replace this page with your own content.</h1>
  </body>
</html>",
}

# https://www.ryadel.com/en/iis-web-config-secure-http-response-headers-pass-securityheaders-io-scan/
# https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/
# https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/denyurlsequences/
# https://www.saotn.org/hackrepair-bad-bots-htaccess-web-config-iis/
# https://www.odity.co.uk/articles/how-to-redirect-http-to-https-with-iis-rewrite-module
file { "${webroot}\\web.config":
  content => "<configuration>
 <system.web>
  <authentication>
    <form cookieless=\"UserCookies\" requireSSL=\"true\" protection=\"All\" />
    <form requireSSL=\"true\" />
  </authentication>
 </system.web>
 <system.webServer>
  <directoryBrowse enabled=\"false\" />
  <httpProtocol>
    <customHeaders>
      <!-- SECURITY HEADERS - https://securityheaders.io/? -->
      <!-- Protects against Clickjacking attacks. ref.: http://stackoverflow.com/a/22105445/1233379 -->
      <add name=\"X-Frame-Options\" value=\"SAMEORIGIN\" />
      <!-- Protects against Clickjacking attacks. ref.: https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet -->
      <add name=\"Strict-Transport-Security\" value=\"max-age=31536000; includeSubDomains\"/>
      <!-- Protects against XSS injections. ref.: https://www.veracode.com/blog/2014/03/guidelines-for-setting-security-headers/ -->
      <add name=\"X-XSS-Protection\" value=\"1; mode=block\" />
      <!-- Protects against MIME-type confusion attack. ref.: https://www.veracode.com/blog/2014/03/guidelines-for-setting-security-headers/ -->
      <add name=\"X-Content-Type-Options\" value=\"nosniff\" />
      <!-- CSP modern XSS directive-based defence, used since 2014. ref.: http://content-security-policy.com/ -->
      <add name=\"Content-Security-Policy\" value=\"default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'self'; upgrade-insecure-requests;\" />
      <!-- Prevents from leaking referrer data over insecure connections. ref.: https://scotthelme.co.uk/a-new-security-header-referrer-policy/ -->
      <add name=\"Referrer-Policy\" value=\"strict-origin\" />

      <customHeaders>
        <remove name=\"X-Powered-By\" />
      </customHeaders>
    </customHeaders>

    <security>
       <requestFiltering allowHighBitCharacters=\"false\" allowDoubleEscaping=\"false\">
          <denyUrlSequences>
             <add sequence=\"..\" />
             <add sequence=\":\" />
             <add sequence=\"\\\" />
             <add sequence=\".conf\" />
             <add sequence=\".config\" />
             <add sequence=\".git\" />
             <add sequence=\".log\" />
             <add sequence=\".old\" />
             <add sequence=\".sec\" />
             <add sequence=\".svn\" />
          </denyUrlSequences>
          <fileExtensions allowUnlisted=\"false\" />
          <requestLimits maxUrl=\"2048\" maxQueryString=\"1024\" maxAllowedContent=\"30000000\" />
          <verbs allowUnlisted=\"false\">
            <add verb=\"TRACE\" allowed=\"false\" />
          </verbs>
       </requestFiltering>
    </security>

    <rewrite>
      <rules>
        <rule name=\"Block Common Malicious Bot Queries\" stopProcessing=\"true\">
          <match url=\".*\" ignoreCase=\"false\" />
          <conditions logicalGrouping=\"MatchAny\">
            <add input=\"{QUERY_STRING}\" pattern=\"http\\:\\/\\/www\\.google\\.com\\/humans\\.txt\\?\" />
            <add input=\"{QUERY_STRING}\" pattern=\"(img|thumb|thumb_editor|thumbopen).php\" />
            <add input=\"{QUERY_STRING}\" pattern=\"fckeditor\" />
            <add input=\"{QUERY_STRING}\" pattern=\"revslider\" />
          </conditions>
          <action type=\"CustomResponse\" statusCode=\"403\" statusReason=\"Forbidden\" statusDescription=\"Forbidden\" />
        </rule>

        <rule name=\"Abuse User Agents Blocking\" stopProcessing=\"true\">
        <!--
          # Blocking user agents stops traffic from the named bots below
          # it matches any bot named below
        -->
          <match url=\".*\" ignoreCase=\"false\" />
          <conditions logicalGrouping=\"MatchAny\">
            <add input=\"{HTTP_USER_AGENT}\" pattern=\"^.*(1Noonbot|1on1searchBot|3D_SEARCH|3DE_SEARCH2|3GSE|50.nu|192.comAgent|360Spider|A6-Indexer|AASP|ABACHOBot|Abonti|abot|AbotEmailSearch|Aboundex|AboutUsBot|AccMonitor\\ Compliance|accoona|AChulkov.NET\\ page\\ walker|Acme.Spider|AcoonBot|acquia-crawler|ActiveTouristBot|Acunetix|Ad\\ Muncher|AdamM|adbeat_bot|adminshop.com|Advanced\\ Email|AESOP_com_SpiderMan|AESpider|AF\\ Knowledge\\ Now\\ Verity|aggregator\\:Vocus|ah-ha.com|AhrefsBot|AIBOT|aiHitBot|aipbot|AISIID|AITCSRobot|Akamai-SiteSnapshot|AlexaWebSearchPlatform|AlexfDownload|Alexibot|AlkalineBOT|All\\ Acronyms|Amfibibot|AmPmPPC.com|AMZNKAssocBot|Anemone|Anonymous|Anonymouse.org|AnotherBot|AnswerBot|AnswerBus|AnswerChase\\ PROve|AntBot|antibot-|AntiSantyWorm|Antro.Net|AONDE-Spider|Aport|Aqua_Products|AraBot|Arachmo|Arachnophilia|archive.org_bot|aria\\ eQualizer|arianna.libero.it|Arikus_Spider|Art-Online.com|ArtavisBot|Artera|ASpider|ASPSeek|asterias|AstroFind|athenusbot|AtlocalBot|Atomic_Email_Hunter|attach|attrakt|attributor|Attributor.comBot|augurfind|AURESYS|AutoBaron|autoemailspider|autowebdir|AVSearch-|axfeedsbot|Axonize-bot|Ayna|b2w|BackDoorBot|BackRub|BackStreet\\ Browser|BackWeb|Baiduspider-video|Bandit|BatchFTP|baypup|BDFetch|BecomeBot|BecomeJPBot|BeetleBot|Bender|besserscheitern-crawl|betaBot|Big\\ Brother|Big\\ Data|Bigado.com|BigCliqueBot|Bigfoot|BIGLOTRON|Bilbo|BilgiBetaBot|BilgiBot|binlar|bintellibot|bitlybot|BitvoUserAgent|Bizbot003|BizBot04|BizBot04\\ kirk.overleaf.com|Black.Hole|Black\\ Hole|Blackbird|BlackWidow|bladder\\ fusion|Blaiz-Bee|BLEXBot|Blinkx|BlitzBOT|Blog\\ Conversation\\ Project|BlogMyWay|BlogPulseLive|BlogRefsBot|BlogScope|Blogslive|BloobyBot|BlowFish|BLT|bnf.fr_bot|BoaConstrictor|BoardReader-Image-Fetcher|BOI_crawl_00|BOIA-Scan-Agent|BOIA.ORG-Scan-Agent|boitho.com-dc|Bookmark\\ Buddy|bosug|Bot\\ Apoena|BotALot|BotRightHere|Botswana|bottybot|BpBot|BRAINTIME_SEARCH|BrokenLinkCheck.com|BrowserEmulator|BrowserMob|BruinBot|BSearchR&amp;D|BSpider|btbot|Btsearch|Buddy|Buibui|BuildCMS|BuiltBotTough|Bullseye|bumblebee|BunnySlippers|BuscadorClarin|Butterfly|BuyHawaiiBot|BuzzBot|byindia|BySpider|byteserver|bzBot|c\\ r\\ a\\ w\\ l\\ 3\\ r|CacheBlaster|CACTVS\\ Chemistry|Caddbot|Cafi|Camcrawler|CamelStampede|Canon-WebRecord|Canon-WebRecordPro|CareerBot|casper|cataguru|CatchBot|CazoodleBot|CCBot|CCGCrawl|ccubee|CD-Preload|CE-Preload|Cegbfeieh|Cerberian\\ Drtrs|CERT\\ FigleafBot|cfetch|CFNetwork|Chameleon|ChangeDetection|Charlotte|Check&amp;Get|Checkbot|Checklinks|checkprivacy|CheeseBot|ChemieDE-NodeBot|CherryPicker|CherryPickerElite|CherryPickerSE|Chilkat|ChinaClaw|CipinetBot|cis455crawler|citeseerxbot|cizilla.com|ClariaBot|clshttp|Clushbot|cmsworldmap|coccoc|CollapsarWEB|Collector|combine|comodo|conceptbot|ConnectSearch|conpilot|ContentSmartz|ContextAd|contype|cookieNET|CoolBott|CoolCheck|Copernic|Copier|CopyRightCheck|core-project|cosmos|Covario-IDS|Cowbot-|Cowdog|crabbyBot|crawl|Crawl_Application|crawl.UserAgent|CrawlConvera|crawler|crawler_for_infomine|CRAWLER-ALTSE.VUNET.ORG-Lynx|crawler-upgrade-config|crawler.kpricorn.org|crawler@|crawler4j|crawler43.ejupiter.com|Crawly|CreativeCommons|Crescent|Crescent\\ Internet\\ ToolPak\\ HTTP\\ OLE\\ Control|cs-crawler|CSE\\ HTML\\ Validator|CSHttpClient|Cuasarbot|culsearch|Curl|Custo|Cutbot|cvaulev|Cyberdog|CyberNavi_WebGet|CyberSpyder|CydralSpider).*$\" />
            <add input=\"{HTTP_USER_AGENT}\" pattern=\"^.*(D1GArabicEngine|DA|DataCha0s|DataFountains|DataparkSearch|DataSpearSpiderBot|DataSpider|Dattatec.com|Dattatec.com-Sitios-Top|Daumoa|DAUMOA-video|DAUMOA-web|Declumbot|Deepindex|deepnet|DeepTrawl|dejan|del.icio.us-thumbnails|DelvuBot|Deweb|DiaGem|Diamond|DiamondBot|diavol|DiBot|didaxusbot|DigExt|Digger|DiGi-RSSBot|DigitalArchivesBot|DigOut4U|DIIbot|Dillo|Dir_Snatch.exe|DISCo|DISCo\\ Pump|discobot|DISCoFinder|Distilled-Reputation-Monitor|Dit|DittoSpyder|DjangoTraineeBot|DKIMRepBot|DoCoMo|DOF-Verify|domaincrawler|DomainScan|DomainWatcher|dotbot|DotSpotsBot|Dow\\ Jonesbot|Download|Download\\ Demon|Downloader|DOY|dragonfly|Drip|drone|DTAAgent|dtSearchSpider|dumbot|Dwaar|Dwaarbot|DXSeeker|EAH|EasouSpider|EasyDL|ebingbong|EC2LinkFinder|eCairn-Grabber|eCatch|eChooseBot|ecxi|EdisterBot|EduGovSearch|egothor|eidetica.com|EirGrabber|ElisaBot|EllerdaleBot|EMail\\ Exractor|EmailCollector|EmailLeach|EmailSiphon|EmailWolf|EMPAS_ROBOT|EnaBot|endeca|EnigmaBot|Enswer\\ Neuro|EntityCubeBot|EroCrawler|eStyleSearch|eSyndiCat|Eurosoft-Bot|Evaal|Eventware|Everest-Vulcan|Exabot|Exabot-Images|Exabot-Test|Exabot-XXX|ExaBotTest|ExactSearch|exactseek.com|exooba|Exploder|explorersearch|extract|Extractor|ExtractorPro|EyeNetIE|ez-robot|Ezooms|factbot|FairAd\\ Client|falcon|Falconsbot|fast-search-engine|FAST\\ Data\\ Document|FAST\\ ESP|fastbot|fastbot.de|FatBot|Favcollector|Faviconizer|FDM|FedContractorBot|feedfinder|FelixIDE|fembot|fetch_ici|Fetch\\ API\\ Request|fgcrawler|FHscan|fido|Filangy|FileHound|FindAnISP.com_ISP_Finder|findlinks|FindWeb|Firebat|Fish-Search-Robot|Flaming\\ AttackBot|Flamingo_SearchEngine|FlashCapture|FlashGet|flicky|FlickySearchBot|flunky|focused_crawler|FollowSite|Foobot|Fooooo_Web_Video_Crawl|Fopper|FormulaFinderBot|Forschungsportal|fr_crawler|Francis|Freecrawl|FreshDownload|freshlinks.exe|FriendFeedBot|frodo.at|froGgle|FrontPage|Froola|FU-NBI|full_breadth_crawler|FunnelBack|FunWebProducts|FurlBot|g00g1e|G10-Bot|Gaisbot|GalaxyBot|gazz|gcreep|generate_infomine_category_classifiers|genevabot|genieBot|GenieBotRD_SmallCrawl|Genieo|Geomaxenginebot|geometabot|GeonaBot|GeoVisu|GermCrawler|GetHTMLContents|Getleft|GetRight|GetSmart|GetURL.rexx|GetWeb!|Giant|GigablastOpenSource|Gigabot|Girafabot|GleameBot|gnome-vfs|Go-Ahead-Got-It|Go!Zilla|GoForIt.com|GOFORITBOT|gold|Golem|GoodJelly|Gordon-College-Google-Mini|goroam|GoSeebot|gotit|Govbot|GPU\\ p2p|grab|Grabber|GrabNet|Grafula|grapeFX|grapeshot|GrapeshotCrawler|grbot|GreenYogi\\ [ZSEBOT]|Gromit|GroupMe|grub|grub-client|Grubclient-|GrubNG|GruBot|gsa|GSLFbot|GT\\:\\:WWW|Gulliver|GulperBot|GurujiBot|GVC|GVC\\ BUSINESS|gvcbot.com|HappyFunBot|harvest|HarvestMan|Hatena\\ Antenna|Hawler|Hazel's\\ Ferret\\ hopper|hcat|hclsreport-crawler|HD\\ nutch\\ agent|Header_Test_Client|healia|Helix|heritrix|hijbul-heritrix-crawler|HiScan|HiSoftware\\ AccMonitor|HiSoftware\\ AccVerify|hitcrawler_|hivaBot|hloader|HMSEbot|HMView|hoge|holmes|HomePageSearch|Hooblybot-Image|HooWWWer|Hostcrawler|HSFT\\ -\\ Link|HSFT\\ -\\ LVU|HSlide|ht\\:|htdig|Html\\ Link\\ Validator|HTMLParser|HTTP\\:\\:Lite|httplib|HTTrack|Huaweisymantecspider|hul-wax|humanlinks|HyperEstraier|Hyperix).*$\" />
            <add input=\"{HTTP_USER_AGENT}\" pattern=\"^.*(ia_archiver|IAArchiver-|ibuena|iCab|ICDS-Ingestion|ichiro|iCopyright\\ Conductor|id-search|IDBot|IEAutoDiscovery|IECheck|iHWebChecker|IIITBOT|iim_405|IlseBot|IlTrovatore|Iltrovatore-Setaccio|ImageBot|imagefortress|ImagesHereImagesThereImagesEverywhere|ImageVisu|imds_monitor|imo-google-robot-intelink|IncyWincy|Industry\\ Cortexcrawler|Indy\\ Library|indylabs_marius|InelaBot|Inet32\\ Ctrl|inetbot|InfoLink|INFOMINE|infomine.ucr.edu|InfoNaviRobot|Informant|Infoseek|InfoTekies|InfoUSABot|INGRID|Inktomi|InsightsCollector|InsightsWorksBot|InspireBot|InsumaScout|Intelix|InterGET|Internet\\ Ninja|InternetLinkAgent|Interseek|IOI|ip-web-crawler.com|IPAdd|Ipselonbot|Iria|IRLbot|Iron33|Isara|iSearch|iSiloX|IsraeliSearch|IstellaBot|its-learning|IU_CSCI_B659_class_crawler|iVia|iVia\\ Page\\ Fetcher|JadynAve|JadynAveBot|jakarta|Jakarta\\ Commons-HttpClient|Java|Jbot|JemmaTheTourist|JennyBot|Jetbot|JetBrains\\ Omea\\ Pro|JetCar|Jim|JoBo|JobSpider_BA|JOC|JoeDog|JoyScapeBot|JSpyda|JubiiRobot|jumpstation|Junut|JustView|Jyxobot|K.S.Bot|KakcleBot|kalooga|KaloogaBot|kanagawa|KATATUDO-Spider|Katipo|kbeta1|Kenjin.Spider|KeywenBot|Keyword.Density|Keyword\\ Density|kinjabot|KIT-Fireball|Kitenga-crawler-bot|KiwiStatus|kmbot-|kmccrew|Knight|KnowItAll|Knowledge.com|Knowledge\\ Engine|KoepaBot|Koninklijke|KrOWLer|KSbot|kuloko-bot|kulturarw3|KummHttp|Kurzor|Kyluka|L.webis|LabelGrab|Labhoo|labourunions411|lachesis|Lament|LamerExterminator|LapozzBot|larbin|LARBIN-EXPERIMENTAL|LBot|LeapTag|LeechFTP|LeechGet|LetsCrawl.com|LexiBot|LexxeBot|lftp|libcrawl|libiViaCore|libWeb|libwww|libwww-perl|likse|Linguee|Link|link_checker|LinkAlarm|linkbot|LinkCheck\\ by\\ Siteimprove.com|LinkChecker|linkdex.com|LinkextractorPro|LinkLint|linklooker|Linkman|LinkScan|LinksCrawler|LinksManager.com_bot|LinkSweeper|linkwalker|LiteFinder|LitlrBot|Little\\ Grabber\\ at\\ Skanktale.com|Livelapbot|LM\\ Harvester|LMQueueBot|LNSpiderguy|LoadTimeBot|LocalcomBot|locust|LolongBot|LookBot|Lsearch|lssbot|LWP|lwp-request|lwp-trivial|LWP\\:\\:Simple|Lycos_Spider|Lydia\\ Entity|LynnBot|Lytranslate|Mag-Net|Magnet|magpie-crawler|Magus|Mail.Ru|Mail.Ru_Bot|MAINSEEK_BOT|Mammoth|MarkWatch|MaSagool|masidani_bot_|Mass|Mata.Hari|Mata\\ Hari|matentzn\\ at\\ cs\\ dot\\ man\\ dot\\ ac\\ dot\\ uk|maxamine.com--robot|maxamine.com-robot|maxomobot|Maxthon$|McBot|MediaFox|medrabbit|Megite|MemacBot|Memo|MendeleyBot|Mercator-|mercuryboard_user_agent_sql_injection.nasl|MerzScope|metacarta|Metager2|metager2-verification-bot|MetaGloss|METAGOPHER|metal|metaquerier.cs.uiuc.edu|METASpider|Metaspinner|MetaURI|MetaURI\\ API|MFC_Tear_Sample|MFcrawler|MFHttpScan|Microsoft.URL|MIIxpc|miner|mini-robot|minibot|miniRank|Mirror|Missigua\\ Locator|Mister.PiX|Mister\\ PiX|Miva|MJ12bot|mnoGoSearch|mod_accessibility|moduna.com|moget|MojeekBot|MOMspider|MonkeyCrawl|MOSES|Motor|mowserbot|MQbot|MSE360|MSFrontPage|MSIECrawler|MSIndianWebcrawl|MSMOBOT|Msnbot|msnbot-products|MSNPTC|MSRBOT|MT-Soft|MultiText|My_Little_SearchEngine_Project|my-heritrix-crawler|MyApp|MYCOMPANYBOT|mycrawler|MyEngines-US-Bot|MyFamilyBot|Myra|nabot|nabot_|Najdi.si|Nambu|NAMEPROTECT|NatchCVS|naver|naverbookmarkcrawler|NaverBot|Navroad|NearSite|NEC-MeshExplorer|NeoScioCrawler|NerdByNature.Bot|NerdyBot|Nerima-crawl-).*$\" />
            <add input=\"{HTTP_USER_AGENT}\" pattern=\"^.*(Nessus|NESSUS\\:\\:SOAP|nestReader|Net\\:\\:Trackback|NetAnts|NetCarta\\ CyberPilot\\ Pro|Netcraft|NetID.com|NetMechanic|Netprospector|NetResearchServer|NetScoop|NetSeer|NetShift=|NetSongBot|Netsparker|NetSpider|NetSrcherP|NetZip|NetZip-Downloader|NewMedhunt|news|News_Search_App|NewsGatherer|Newsgroupreporter|NewsTroveBot|NextGenSearchBot|nextthing.org|NG|NHSEWalker|nicebot|NICErsPRO|niki-bot|NimbleCrawler|nimbus-1|ninetowns|Ninja|NjuiceBot|NLese|Nogate|Nomad-V2.x|NoteworthyBot|NPbot|NPBot-|NRCan\\ intranet|NSDL_Search_Bot|nu_tch-princeton|nuggetize.com|nutch|nutch1|NutchCVS|NutchOrg|NWSpider|Nymesis|nys-crawler|ObjectsSearch|oBot|Obvius\\ external\\ linkcheck|Occam|Ocelli|Octopus|ODP\\ entries|Offline.Explorer|Offline\\ Explorer|Offline\\ Navigator|OGspider|OmiExplorer_Bot|OmniExplorer_Bot|omnifind|OmniWeb|OnetSzukaj|online\\ link\\ validator|OOZBOT|Openbot|Openfind|Openfind\\ data|OpenHoseBot|OpenIntelligenceData|OpenISearch|OpenSearchServer_Bot|OpiDig|optidiscover|OrangeBot|ORISBot|ornl_crawler_1|ORNL_Mercury|osis-project.jp|OsO|OutfoxBot|OutfoxMelonBot|OWLER-BOT|owsBot|ozelot|P3P\\ Client|page_verifier|PageBitesHyperBot|Pagebull|PageDown|PageFetcher|PageGrabber|PagePeeker|PageRank\\ Monitor|pamsnbot.htm|Panopy|panscient.com|Pansophica|Papa\\ Foto|PaperLiBot|parasite|parsijoo|Pathtraq|Pattern|Patwebbot|pavuk|PaxleFramework|PBBOT|pcBrowser|pd-crawler|PECL\\:\\:HTTP|penthesila|PeoplePal|perform_crawl|PerMan|PGP-KA|PHPCrawl|PhpDig|PicoSearch|pipBot|pipeLiner|Pita|pixfinder|PiyushBot|planetwork|PleaseCrawl|Plucker|Plukkie|Plumtree|Pockey|Pockey-GetHTML|PoCoHTTP|pogodak.ba|Pogodak.co.yu|Poirot|polybot|Pompos|Poodle\\ predictor|PopScreenBot|PostPost|PrivacyFinder|ProjectWF-java-test-crawler|ProPowerBot|ProWebWalker|PROXY|psbot|psbot-page|PSS-Bot|psycheclone|pub-crawler|pucl|pulseBot\\ \\(pulse|Pump|purebot|PWeBot|pycurl|Python-urllib|pythonic-crawler|PythonWikipediaBot|q1|QEAVis\\ agent|QFKBot|qualidade|Qualidator.com|QuepasaCreep|QueryN.Metasearch|QueryN\\ Metasearch|quest.durato|Quintura-Crw|QunarBot|Qweery_robot.txt_CheckBot|QweeryBot|r2iBot|R6_CommentReader|R6_FeedFetcher|R6_VoteReader|RaBot|Radian6|radian6_linkcheck|RAMPyBot|RankurBot|RcStartBot|RealDownload|Reaper|REBI-shoveler|Recorder|RedBot|RedCarpet|ReGet|RepoMonkey|RepoMonkey\\ Bait|Riddler|RIIGHTBOT|RiseNetBot|RiverglassScanner|RMA|RoboPal|Robosourcer|robot|robotek|robots|Robozilla|rogerBot|Rome\\ Client|Rondello|Rotondo|Roverbot|RPT-HTTPClient|rtgibot|RufusBot|Runnk\\ online\\ rss\\ reader|s~stremor-crawler|S2Bot|SafariBookmarkChecker|SaladSpoon|Sapienti|SBIder|SBL-BOT|SCFCrawler|Scich|ScientificCommons.org|ScollSpider|ScooperBot|Scooter|ScoutJet|ScrapeBox|Scrapy|SCrawlTest|Scrubby|scSpider|Scumbot|SeaMonkey$|Search-Channel|Search-Engine-Studio|search.KumKie.com|search.msn.com|search.updated.com|search.usgs.gov|Search\\ Publisher|Searcharoo.NET|SearchBlox|searchbot|searchengine|searchhippo.com|SearchIt-Bot|searchmarking|searchmarks|searchmee_v|SearchmetricsBot|searchmining|SearchnowBot_v1|searchpreview|SearchSpider.com|SearQuBot|Seekbot|Seeker.lookseek.com|SeeqBot|seeqpod-vertical-crawler|Selflinkchecker|Semager|semanticdiscovery|Semantifire1|semisearch|SemrushBot|Senrigan|SEOENGWorldBot|SeznamBot|ShablastBot|ShadowWebAnalyzer|Shareaza|Shelob|sherlock|ShopWiki|ShowLinks|ShowyouBot|siclab|silk|Siphon|SiteArchive|SiteCheck-sitecrawl|sitecheck.internetseer.com|SiteFinder|SiteGuardBot|SiteOrbiter|SiteSnagger|SiteSucker|SiteSweeper|SiteXpert|SkimBot|SkimWordsBot|SkreemRBot|skygrid|Skywalker|Sleipnir|slow-crawler|SlySearch|smart-crawler|SmartDownload|Smarte|smartwit.com|Snake|Snapbot|SnapPreviewBot|Snappy|snookit|Snooper|Snoopy|SocialSearcher|SocSciBot|SOFT411\\ Directory|sogou|sohu-search|sohu\\ agent|Sokitomi|Solbot|sootle|Sosospider|Space\\ Bison|Space\\ Fung|SpaceBison|SpankBot|spanner|Spatineo\\ Monitor\\ Controller|special_archiver|SpeedySpider|Sphider|Sphider2|spider|Spider.TerraNautic.net|SpiderEngine|SpiderKU|SpiderMan|Spinn3r|Spinne|sportcrew-Bot|spyder3.microsys.com|sqlmap|Squid-Prefetch|SquidClamAV_Redirector|Sqworm|SrevBot|sslbot|SSM\\ Agent|StackRambler|StarDownloader|statbot|statcrawler|statedept-crawler|Steeler|STEGMANN-Bot|stero|Stripper|Stumbler|suchclip|sucker|SumeetBot|SumitBot|SummizeBot|SummizeFeedReader|SuperBot|superbot.com|SuperHTTP|SuperLumin|SuperPagesBot|Supybot|SURF|Surfbot|SurfControl|SurveyBot|suzuran|SWEBot|swish-e|SygolBot|SynapticWalker|Syntryx\\ ANT\\ Scout\\ Chassis\\ Pheromone|SystemSearch-robot|Szukacz).*$\" />
            <add input=\"{HTTP_USER_AGENT}\" pattern=\"^.*(T-H-U-N-D-E-R-S-T-O-N-E|Tailrank|tAkeOut|TAMU_CRAWLER|TapuzBot|Tarantula|targetblaster.com|TargetYourNews.com|TAUSDataBot|taxinomiabot|Tecomi|TeezirBot|Teleport|Teleport\\ Pro|TeleportPro|Telesoft|Teradex\\ Mapper|TERAGRAM_CRAWLER|TerrawizBot|testbot|testing\\ of|TextBot|thatrobotsite.com|The.Intraformant|The\\ Dyslexalizer|The\\ Intraformant|TheNomad|Theophrastus|theusefulbot|TheUsefulbot_|ThumbBot|thumbshots-de-bot|tigerbot|TightTwatBot|TinEye|Titan|to-dress_ru_bot_|to-night-Bot|toCrawl|Topicalizer|topicblogs|Toplistbot|TopServer\\ PHP|topyx-crawler|Touche|TourlentaScanner|TPSystem|TRAAZI|TranSGeniKBot|travel-search|TravelBot|TravelLazerBot|Treezy|TREX|TridentSpider|Trovator|True_Robot|tScholarsBot|TsWebBot|TulipChain|turingos|turnit|TurnitinBot|TutorGigBot|TweetedTimes|TweetmemeBot|TwengaBot|TwengaBot-Discover|Twiceler|Twikle|twinuffbot|Twisted\\ PageGetter|Twitturls|Twitturly|TygoBot|TygoProwler|Typhoeus|U.S.\\ Government\\ Printing\\ Office|uberbot|ucb-nutch|UCSD-Crawler|UdmSearch|UFAM-crawler-|Ultraseek|UnChaos|unchaos_crawler_|UnisterBot|UniversalSearch|UnwindFetchor|UofTDB_experiment|updated|URI\\:\\:Fetch|url_gather|URL-Checker|URL\\ Control|URLAppendBot|URLBlaze|urlchecker|urlck|UrlDispatcher|urllib|URLSpiderPro|URLy.Warning|USAF\\ AFKN|usasearch|USS-Cosmix|USyd-NLP-Spider|Vacobot|Vacuum|VadixBot|Vagabondo|Validator|Valkyrie|vBSEO|VCI|VerbstarBot|VeriCiteCrawler|Verifactrola|Verity-URL-Gateway|vermut|versus|versus.integis.ch|viasarchivinginformation.html|vikspider|VIP|VIPr|virus-detector|VisBot|Vishal\\ For\\ CLIA|VisWeb|vlad|vlsearch|VMBot|VocusBot|VoidEYE|VoilaBot|Vortex|voyager|voyager-hc|voyager-partner-deep|VSE|vspider).*$\" />
            <add input=\"{HTTP_USER_AGENT}\" pattern=\"^.*(W3C_Unicorn|W3C-WebCon|w3m|w3search|wacbot|wastrix|Water\\ Conserve|Water\\ Conserve\\ Portal|WatzBot|wauuu\\ engine|Wavefire|Waypath|Wazzup|Wazzup1.0.4800|wbdbot|web-agent|Web-Sniffer|Web.Image.Collector|Web\\ CEO\\ Online|Web\\ Image\\ Collector|Web\\ Link\\ Validator|Web\\ Magnet|webalta|WebaltBot|WebAuto|webbandit|webbot|webbul-bot|WebCapture|webcheck|Webclipping.com|webcollage|WebCopier|WebCopy|WebCorp|webcrawl.net|webcrawler|WebDownloader\\ for|Webdup|WebEMailExtrac|WebEMailExtrac.*|WebEnhancer|WebFerret|webfetch|WebFetcher|WebGather|WebGo\\ IS|webGobbler|WebImages|Webinator-search2.fasthealth.com|Webinator-WBI|WebIndex|WebIndexer|weblayers|WebLeacher|WeblexBot|WebLinker|webLyzard|WebmasterCoffee|WebmasterWorld|WebmasterWorldForumBot|WebMiner|WebMoose|WeBot|WebPix|WebReaper|WebRipper|WebSauger|Webscan|websearchbench|WebSite|websitemirror|WebSpear|websphinx.test|WebSpider|Webster|Webster.Pro|Webster\\ Pro|WebStripper|WebTrafficExpress|WebTrends\\ Link\\ Analyzer|webvac|webwalk|WebWalker|Webwasher|WebWatch|WebWhacker|WebXM|WebZip|Weddings.info|wenbin|WEPA|WeRelateBot|Whacker|Widow|WikiaBot|Wikio|wikiwix-bot-|WinHttp.WinHttpRequest|WinHTTP\\ Example|WIRE|wired-digital-newsbot|WISEbot|WISENutbot|wish-la|wish-project|wisponbot|WMCAI-robot|wminer|WMSBot|woriobot|worldshop|WorQmada|Wotbox|WPScan|wume_crawler|WWW-Mechanize|www.freeloader.com.|WWW\\ Collector|WWWOFFLE|wwwrobot|wwwster|WWWWanderer|wwwxref|Wysigot|X-clawler|Xaldon|Xenu|Xenu's|Xerka\\ MetaBot|XGET|xirq|XmarksFetch|XoviBot|xqrobot|Y!J|Y!TunnelPro|yacy.net|yacybot|yarienavoir.net|Yasaklibot|yBot|YebolBot|yellowJacket|yes|YesupBot|Yeti|YioopBot|YisouSpider|yolinkBot|yoogliFetchAgent|yoono|Yoriwa|YottaCars_Bot|you-dir|Z-Add\\ Link|zagrebin|Zao|zedzo.digest|zedzo.validate|zermelo|Zeus|Zeus\\ Link\\ Scout|zibber-v|zimeno|Zing-BottaBot|ZipppBot|zmeu|ZoomSpider|ZuiBot|ZumBot|Zyborg|Zyte).*$\" />
          </conditions>
          <action type=\"CustomResponse\" statusCode=\"403\" statusReason=\"Forbidden\" statusDescription=\"Forbidden\" />
        </rule>
      </rules>

      <outboundRules rewriteBeforeCache=\"true\">
        <rule name=\"Remove Server header\">
          <match serverVariable=\"RESPONSE_Server\" pattern=\".+\" />
          <action type=\"Rewrite\" value=\"\" />
        </rule>
      </outboundRules>
    </rewrite>

  </httpProtocol>
 </system.webServer>
</configuration>",
}

# FIXME!
# appveyor: puppet : Error: Error updating apppool: Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
# vagrant: OK
iis_application_pool { 'complete_site_app_pool':
  ensure                  => 'present',
  state                   => 'started',
  managed_pipeline_mode   => 'Integrated',
  managed_runtime_version => 'v4.0',
  auto_start              => true,
  enable32_bit_app_on_win64 => false,
# default: 20 (min)
  idle_timeout            => '00:20:00',
# To load web.config. normally in web root folder
  enable_configuration_override => true,
# https://docs.microsoft.com/en-us/iis/get-started/planning-your-iis-architecture/getting-started-with-configuration-in-iis-7-and-above
# https://msdn.microsoft.com/en-us/library/bb763179.aspx
}

iis_application_pool {'test_app_pool':
    ensure                    => 'present',
    enable32_bit_app_on_win64 => true,
    managed_runtime_version   => '""',
    managed_pipeline_mode     => 'Classic',
    start_mode                => 'AlwaysRunning'
  }

iis_site { 'complete':
  ensure           => 'started',
  physicalpath     => "${webroot}",
  applicationpool  => 'complete_site_app_pool',
  enabledprotocols => [ 'http', 'https' ],
  bindings         => [
    {
      'bindinginformation'   => '*:80:',
      'protocol'             => 'http',
    },
#    {
#      'bindinginformation'   => '*:443:',
#      'protocol'             => 'https',
#      'certificatehash'      => $facts['webserver_certhash'],
#      'certificatestorename' => 'MY',
#      'sslflags'             => 1,
#    },
  ],
  logformat => 'W3C',
  logpath   => "${logpath}",
  logperiod => 'Daily',
  limits => {
    connectiontimeout => 120,
    maxbandwidth      => 4294967200,
    maxconnections    => 4294967200,
  },
  require => File["${webroot}"],
}

iis_virtual_directory { 'vdir':
  ensure       => 'present',
  sitename     => 'complete',
  physicalpath => 'c:\\inetpub\\complete_vdir',
  require      => File['c:\\inetpub\\complete_vdir'],
}

# https://blogs.msdn.microsoft.com/varunm/2013/04/23/remove-unwanted-http-response-headers/
# https://ruslany.net/2008/07/scripting-url-rewrite-module-configuration/
# or chocolatey: urlrewrite
#class { 'iis_rewrite':
##  package_source_location => 'http://myhost.com/package231.msi'
#}

file { "${webroot}\\.well-known":
  ensure    => directory,
}
file { "${webroot}\\.well-known\\security.txt":
  ensure    => present,
  content   => "Contact: mailto:security@example.com
Contact: +1-201-555-0123
Contact: https://example.com/security
Encryption: https://example.com/pgp-key.txt
Disclosure: Full
Acknowledgement: https://example.com/hall-of-fame.html",
}

# https://docs.microsoft.com/en-us/iis/web-hosting/web-server-for-shared-hosting/application-pool-identity-as-anonymous-user
# https://kevinareed.com/2015/11/07/how-to-deploy-anything-in-iis-with-zero-downtime-on-a-single-server/
