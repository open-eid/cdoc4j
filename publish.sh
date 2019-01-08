#!/bin/bash

project="cdoc4j"
version="1.3"
staging_url="https://oss.sonatype.org/service/local/staging/deploy/maven2/"
repositoryId="ossrh"

# Starting GPG agent to store GPG passphrase so we wouldn't have to enter the passphrase every time
eval $(gpg-agent --daemon --no-grab)
export GPG_TTY=$(tty)
export GPG_AGENT_INFO

artifact="target/$project-$version"

echo "Deploying $project-$version"

mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=$artifact.jar -Durl=$staging_url -DrepositoryId=$repositoryId
mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=$artifact-sources.jar -Dclassifier=sources -Durl=$staging_url -DrepositoryId=$repositoryId
mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=$artifact-javadoc.jar -Dclassifier=javadoc -Durl=$staging_url -DrepositoryId=$repositoryId

echo "Finished deployment"

killall gpg-agent
