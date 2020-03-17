#!/bin/bash
function vulnScan() {
	os=$(uname -s)
	arc=$(uname -i)
	local softList=()
	while read row; do
		softList+=($row)
	done < <(rpm -qai|grep -E '^(Version[[:space:]]+:|Name[[:space:]]+:)'|sed -e 's/[[:space:]]\{1,\}/ /g'|cut -d' ' -f3)
	vulnScanList="["
	osname=$(cat "/etc/redhat-release")
	for ((i=0;i<${#softList[@]};i=$i+2)); do
		if [[ $i == 0 ]]; then
			tmpScan="[\"${softList[$i]}\",\"${softList[(($i+1))]}\",\"$osname\"]"
		else
			tmpScan=",[\"${softList[$i]}\",\"${softList[(($i+1))]}\",\"$osname\"]"
		fi
		vulnScanList+="$tmpScan"
	done
	vulnScanList+="]"
	vulnScanResult={\"os\":\"$os\",\"arc\":\"$arc\",\"vulnScanList\":$vulnScanList}
	export vulnScanResult
#	echo $vulnScanResult|jq
}
