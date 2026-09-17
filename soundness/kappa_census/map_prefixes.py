import subprocess, zipfile, os, sys, json
PREFIXES = ["java","javax","jakarta","jdk","sun","com.sun","kotlin","kotlinx","scala","groovy",
 "org.codehaus.groovy","org.jetbrains","org.springframework","io.ktor","org.slf4j",
 "org.apache.logging","ch.qos.logback","org.apache.commons.logging","org.apache.commons.lang3",
 "org.joda.time","org.hibernate.criterion","org.apache.struts","org.apache.commons.validator",
 "org.apache.commons.beanutils","org.threeten.extra","io.jsonwebtoken","org.jdom2","org.displaytag",
 "org.ehcache","org.w3c.dom","com.fasterxml.jackson","com.csvreader","org.supercsv",
 "org.apache.commons.codec","org.apache.commons.lang","org.apache.commons.csv",
 "com.opensymphony.oscache","com.google.common.base","com.google.common.math","com.google.maps.model",
 "org.apache.xml.serialize","org.xml.sax","org.aopalliance","com.twilio","org.redisson","org.dbunit",
 "org.hibernate.engine.jdbc.internal","org.hibernate.boot.model.naming","org.hibernate.jpa",
 "io.awspring.cloud.ses","software.amazon.awssdk.auth.credentials","org.postgresql.util"]
LIB="soundness/lib"
hits = {p: {} for p in PREFIXES}
for jar in sorted(os.listdir(LIB)):
    if not jar.endswith(".jar"): continue
    try: names = zipfile.ZipFile(os.path.join(LIB,jar)).namelist()
    except Exception: continue
    pkgs = set()
    for n in names:
        if n.endswith(".class"):
            d = n.rsplit("/",1)[0].replace("/",".")
            pkgs.add(d)
    for p in PREFIXES:
        c = sum(1 for d in pkgs if d==p or d.startswith(p+"."))
        if c: hits[p][jar]=c
print(json.dumps(hits, indent=0))
