#!/bin/bash

# Copyright 2015-2016 F5 Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

shopt -s extglob
source /config/os-functions/openstack-datasource.sh

# BIG-IP licensing settings
readonly BIGIP_LICENSE_FILE="/config/bigip.license"
readonly BIGIP_LICENSE_RETRIES=5
readonly BIGIP_LICENSE_RETRY_INTERVAL=5

# BIG-IP module provisioning
readonly BIGIP_PROVISIONING_ENABLED=true
readonly BIGIP_AUTO_PROVISIONING_ENABLED=true

readonly LEVEL_REGEX='^(dedicated|minimum|nominal|none)$'


# get BIG-IQ auth token
function get_bigiq_token() {
	# arguments bigiq_hostname bigiq_username bigiq_password
	req_url="https://$1/mgmt/shared/authn/login"
	curl_out=$( curl -X POST -d "{\"username\": \"${2}\", \"password\": \"${3}\"}" -qSfksw '\n%{http_code}' $req_url ) 
    curl_status=$?
	if [[ $curl_status -eq 0 ]] ; then
		http_status=$(echo "$curl_out"| tail -n1)
        if [[ $http_status -eq 200 ]] ; then
            response_body=$(echo "$curl_out"| head -n -1)
            echo -n $(echo "$response_body" | perl -MJSON -le 'undef $/; $_=<STDIN>; print decode_json($_)->{token}->{token}');
        fi
	fi
}

# get BIG-IQ license pool uuid by its pool name
function get_license_pool_uuid() {
	# arguments bigiq_hostname bigiq_token bigiq_pool_name
	req_url="https://$1/mgmt/cm/shared/licensing/pools"
	curl_out=$( curl -H "X-F5-Auth-Token: $2" -qSfksw '\n%{http_code}' $req_url ) 
    curl_status=$?
	if [[ $curl_status -eq 0 ]] ; then
		http_status=$(echo "$curl_out"| tail -n1)
        if [[ $http_status -eq 200 ]] ; then
            response_body=$(echo "$curl_out"| head -n -1)
            echo -n $(echo "$response_body" | \
            perl -MJSON -le "undef \$/; \$_=<STDIN>; foreach \$p (@{decode_json(\$_)->{items}}) { if(\$p->{name} eq \"${3}\") { print \$p->{uuid}; } }")
        fi
	fi
}

# kick-off license process for an unmanaged member in a BIG-IQ license pool
function license_unmanaged_member() {
	# arguments bigiq_hostname bigiq_token bigiq_pool_uuid bigip_hostname bigip_username bigip_password
    req_url="https://$1/mgmt/cm/shared/licensing/pools/$3/members"
    data="{\"deviceAddress\": \"${4}\", \"username\": \"${5}\", \"password\": \"${6}\"}"
	curl_out=$( curl -X POST -d "$data" -H "X-F5-Auth-Token: $2" -qSfksw '\n%{http_code}' $req_url ) 
    curl_status=$?
	if [[ $curl_status -eq 0 ]] ; then
	    http_status=$(echo "$curl_out"| tail -n1)
        if [[ $http_status -eq 200 ]] ; then
            response_body=$(echo "$curl_out"| head -n -1)
            echo -n $(echo "$response_body" | perl -MJSON -le 'undef $/; $_=<STDIN>; print decode_json($_)->{uuid}');
        fi
	fi
}

# get BIG-IQ license pool member uuid by member's registered device address
function get_license_pool_member_uuid() {
    # arguments bigiq_hostname bigiq_token bigiq_pool_uuid member_device_address
    req_url="https://$1/mgmt/cm/shared/licensing/pools/$3/members"
    curl_out=$( curl -H "X-F5-Auth-Token: $2" -qSfksw '\n%{http_code}' $req_url )
    curl_status=$?
	if [[ $curl_status -eq 0 ]] ; then
	    http_status=$(echo "$curl_out"| tail -n1)
        if [[ $http_status -eq 200 ]] ; then
            response_body=$(echo "$curl_out"| head -n -1)
            echo -n $(echo "$response_body" | \
            perl -MJSON -le "undef \$/; \$_=<STDIN>; foreach \$p (@{decode_json(\$_)->{items}}) { if(\$p->{deviceAddress} eq \"${4}\") { print \$p->{uuid}; } }")
        fi
	fi
}

# kick-off license revocation process on BIG-IQ for an unmanaged pool member
function revoke_unmanaged_member() {
	# arguments bigiq_hostname bigiq_token bigiq_pool_uuid member_uuid bigip_username bigip_password
    req_url="https://$1/mgmt/cm/shared/licensing/pools/$3/members/$4"
    data="{\"uuid\": \"${4}\", \"username\": \"${5}\", \"password\": \"${6}\"}"
    curl_out=$( curl -X DELETE -d "$data" -H "X-F5-Auth-Token: $2" -qSfksw '\n%{http_code}' $req_url )
    curl_status=$?
	if [[ $curl_status -eq 0 ]] ; then
	    http_status=$(echo "$curl_out"| tail -n1)
        if [[ $http_status -eq 200 ]] ; then
            echo 1;
        else
            echo 0;
        fi
	fi
}

# get the license state of an unmanaged pool member in a BIG-IQ license pool
function get_pool_member_license_state() {
    # arguments bigiq_hostname bigiq_token bigiq_pool_uuid member_uuid	
	req_url="https://$1/mgmt/cm/shared/licensing/pools/$3/members/$4"
    curl_out=$( curl -H "X-F5-Auth-Token: $2" -qSfksw '\n%{http_code}' $req_url )
    curl_status=$?
	if [[ $curl_status -eq 0 ]] ; then
	    http_status=$(echo "$curl_out"| tail -n1)
        if [[ $http_status -eq 200 ]] ; then
            response_body=$(echo "$curl_out"| head -n -1)
            echo -n $(echo "$response_body" | perl -MJSON -le 'undef $/; $_=<STDIN>; print decode_json($_)->{state}');
        fi
	fi
}

# license and provision device if license file doesn't exist
function license_and_provision_modules() {
    if [[ ! -s ${BIGIP_LICENSE_FILE} ]]; then
	license_bigip
	provision_modules
    else
	log "Skip licensing and provisioning.  "${BIGIP_LICENSE_FILE}" already exists."
    fi
}

# extract license from JSON data and license unit
function license_bigip() {
    local host=$(get_user_data_value {bigip}{license}{host})
    local basekey=$(get_user_data_value {bigip}{license}{basekey})
    local addkey=$(get_user_data_value {bigip}{license}{addkey})

    if [[ -f /etc/init.d/mysql ]]; then
	sed -ised -e 's/sleep\ 5/sleep\ 10/' /etc/init.d/mysql
	rm -f /etc/init.d/mysqlsed
    fi

    if [[ ! -s ${BIGIP_LICENSE_FILE} ]]; then
	    if [[ ! $(is_false $basekey) ]]; then
	        failed=0
	        # if a host or add-on key is provided, append to license client command
	        [[ ! $(is_false $host) ]] && host_cmd="--host $host"
	        [[ ! $(is_false $addkey) ]] && addkey_cmd="--addkey $addkey"

	        while true; do
		        log "Licensing BIG-IP using license key $basekey..."
		        /usr/local/bin/SOAPLicenseClient $host_cmd --basekey $basekey $addkey_cmd 2>&1 | eval $LOGGER_CMD
		        if [[ $? == 0 && -f $BIGIP_LICENSE_FILE ]]; then
		            log "Successfully licensed BIG-IP using user-data from instance metadata..."
		            return 0
		        else
		            failed=$(($failed + 1))
    		        if [[ $failed -ge ${BIGIP_LICENSE_RETRIES} ]]; then
	        	    	log "Failed to license BIG-IP after $failed attempts, quitting..."
	        		    return 1
		            fi
    		        log "Could not license BIG-IP (attempt #$failed/$BIGIP_LICENSE_RETRIES), retrying in $BIGIP_LICENSE_RETRY_INTERVAL seconds..."
	    	        sleep ${BIGIP_LICENSE_RETRY_INTERVAL}
	        	fi
	        done
	    else
    	    local bigiqhost=$(get_user_data_value {bigip}{license}{bigiqhost})
	        local bigiqusername=$(get_user_data_value {bigip}{license}{bigiqusername})
	        local bigiqpassword=$(get_user_data_value {bigip}{license}{bigiqpassword})
	        local bigiqlicensepoolname=$(get_user_data_value {bigip}{license}{bigiqlicensepoolname})
            if [[ -z $bigiqhost || -z $bigiqusername || -z $bigiqpassword || -z bigiqlicensepoolname ]]; then
                log "No BIG-IP license key found or missing BIG-IQ required settings, skipping license activation..."    
            else
                bigiq_token=$(get_bigiq_token "$bigiqhost" "$bigiqusername" "$bigiqpassword")
                # check for bigiq token
                if [[ -n $bigiq_token ]]; then 
                
                    log "Session established with BIG-IQ.. finding license pool $bigiqlicensepoolname"
                    pool_uuid=$(get_license_pool_uuid "$bigiqhost" "$bigiq_token" "$bigiqlicensepoolname")
                    if [[ -n $pool_uuid ]]; then

                        bigiphost=$(get_mgmt_ip)
                        log "licensing from mgmt IP $bigiphost"
                    
                        member_uuid=$(get_license_pool_member_uuid "$bigiqhost" "$bigiq_token" "$pool_uuid" "$bigiphost")
                        if [[ -n $member_uuid ]]; then
                    
                            log "deleting existing license for $bigiphost - $member_uuid"
                            deleted=$(revoke_unmanaged_member "$bigiqhost" "$bigiq_token" "$pool_uuid" "$member_uuid")
                            if [[ -n $deleted ]]; then
                            
                                rand_password=`< /dev/urandom tr -dc A-Z | head -c10`
                                tmsh list /auth user licensor one-line
                                if [[ $? == 1 ]]; then 
                                    log "creating license activation user"
                                    tmsh create /auth user licensor role admin partition-access all shell tmsh password $rand_password
                                else
                                    log "updating password for existing license activation user"
                                    password_hash=$(generate_sha512_passwd_hash "$rand_password")
                                    sed -e "/auth user $user/,/}/ s|\(encrypted-password \).*\$|\1\"$password_hash\"|" \
		                            -i /config/bigip_user.conf
		                            tmsh load sys config user-only 2>&1 | eval $LOGGER_CMD
                                fi
                            
                                log "requesting BIG-IQ license activation for $bigiphost"
                                member_uuid=$(license_unmanaged_member "$bigiqhost" "$bigiq_token" "$pool_uuid" "$bigiphost" "licensor" "$rand_password")

                                if [[ -n $member_uuid ]]; then
                                    log "BIG-IQ license activation for $bigiphost from $bigiqlicensepoolname requested for member ID: $member_uuid"
                                    while true; do
		                                log "Checking license status..."
		                                local license_status=$(get_pool_member_license_state "$bigiqhost" "$bigiq_token" "$pool_uuid" "$member_uuid")	
                                        if [[ $local_license_status == 'LICENSED' ]]; then
                                            log "Successfully licensed BIG-IP from BIG-IQ license pool $bigiqlicensepoolname..."
		                                    return 0
		                                else
		                                    failed=$(($failed + 1))
		                                    if [[ $failed -ge ${BIGIP_LICENSE_RETRIES} ]]; then
			                                    log "BIG-IP in license state $license_status after $failed attempts, quitting..."
			                                    return 1
		                                    fi
		                                    log "BIG-IP in license state $license_status (attempt #$failed/$BIGIP_LICENSE_RETRIES), retrying in $BIGIP_LICENSE_RETRY_INTERVAL seconds..."
		                                    sleep ${BIGIP_LICENSE_RETRY_INTERVAL}
		                                fi
	                                done
                                fi
                            
                            else
                                log "could not delete existing license record for $bigiphost, skipping license activation..."
                                return 1
                            fi
                    
                        else
                        
                            # license new host 
                                      
                            rand_password=`< /dev/urandom tr -dc A-Z | head -c10`
                            tmsh list /auth user licensor one-line
                            if [[ $? == 1 ]]; then 
                                log "creating license activation user"
                                tmsh create /auth user licensor role admin partition-access all shell tmsh password $rand_password
                            else
                                log "updating password for existing license activation user"
                                password_hash=$(generate_sha512_passwd_hash "$rand_password")
                                sed -e "/auth user $user/,/}/ s|\(encrypted-password \).*\$|\1\"$password_hash\"|" \
		                        -i /config/bigip_user.conf
		                        tmsh load sys config user-only 2>&1 | eval $LOGGER_CMD
                            fi
                            log "requesting BIG-IQ license activation for $bigiphost"
                            member_uuid=$(license_unmanaged_member "$bigiqhost" "$bigiq_token" "$pool_uuid" "$bigiphost" "licensor" "$rand_password")
                            if [[ -n $member_uuid ]]; then
                                log "BIG-IQ license activation for $bigiphost from $bigiqlicensepoolname requested for member ID: $member_uuid"
                                while true; do
		                            log "Checking license status..."
		                            local license_status=$(get_pool_member_license_state "$bigiqhost" "$bigiq_token" "$pool_uuid" "$member_uuid")	
                                    if [[ $local_license_status == 'LICENSED' ]]; then
                                        log "Successfully licensed BIG-IP from BIG-IQ license pool $bigiqlicensepoolname..."
		                                return 0
		                            else
		                                failed=$(($failed + 1))
		                                if [[ $failed -ge ${BIGIP_LICENSE_RETRIES} ]]; then
			                                log "BIG-IP in license state $license_status after $failed attempts, quitting..."
			                                return 1
		                                fi
		                                log "BIG-IP in license state $license_status (attempt #$failed/$BIGIP_LICENSE_RETRIES), retrying in $BIGIP_LICENSE_RETRY_INTERVAL seconds..."
		                                sleep ${BIGIP_LICENSE_RETRY_INTERVAL}
		                            fi
	                            done
                            fi
                        
                        
                        fi
                    
                    else
                        log "Could not find BIG-IQ license pool $bigiqlicensepoolname, skipping activation..."
                        return 1
                    fi    
                
                else
                    log "Could not get an BIG-IQ authorization token, skipping license activation..."
                    return 1
                fi
            fi
        fi
    else
	    log "BIG-IP already licensed, skipping license activation..."
    fi
}

# return list of modules supported by current platform
function get_supported_modules() {
    echo -n $(tmsh list sys provision one-line | awk '/^sys/ { print $3 }')
}

# retrieve enabled modules from BIG-IP license file
function get_licensed_modules() {
    if [[ -s $BIGIP_LICENSE_FILE ]]; then
	provisionable_modules=$(get_supported_modules)
	enabled_modules=$(awk '/^mod.*enabled/ { print $1 }' /config/bigip.license |
	    sed 's/mod_//' | tr '\n' ' ')

	for module in $enabled_modules; do
	    case $module in
		wo@(c|m)) module="wom" ;;
		wa?(m)) module="wam" ;;
		af@(m|w)) module="afm" ;;
		am) module="apm" ;;
	    esac

	    if [[ "$provisionable_modules" == *"$module"* ]]; then
		licensed_modules="$licensed_modules $module"
		log "Found license for $(upcase $module) module..."
	    fi
	done

	echo "$licensed_modules"
    else
    	log "Could not locate valid BIG-IP license file, no licensed modules found..."
    fi
}

# provision BIG-IP software modules
function provision_modules() {
    # get list of licensed modules
    local licensed_modules=$(get_licensed_modules)
    local provisionable_modules=$(get_supported_modules)

    # if auto-provisioning enabled, obtained enabled modules list from license file
    local auto_provision=$(get_user_data_value {bigip}{modules}{auto_provision})
    [[ $BIGIP_AUTO_PROVISIONING_ENABLED == false ]] && auto_provision=false

    for module in $licensed_modules; do
	level=$(get_user_data_value {bigip}{modules}{$module})

	if [[ "$provisionable_modules" == *"$module"* ]]; then
	    if [[ ! $level =~ $LEVEL_REGEX ]]; then
		if [[ $auto_provision == true ]]; then
		    level=nominal
		else
		    level=none
		fi
	    fi

	    tmsh modify sys provision $module level $level &> /dev/null

	    if [[ $? == 0 ]]; then
		log "Successfully provisioned $(upcase "$module") with level $level..."
	    else
		log "Failed to provision $(upcase "$module"), examine /var/log/ltm for more information..."
	    fi
	fi
    done
}

function test() {
    license_bigip
    if [[ $? == 0 ]]; then
	echo "license_bigip successful"
    else
	echo "license_bigip unsuccessful"
    fi
}

#test
