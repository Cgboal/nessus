package nessus

var BasicTemplate string = "{\"uuid\":\"731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65\",\"credentials\":{\"add\":{},\"edit\":{},\"delete\":[]},\"settings\":{\"patch_audit_over_rexec\":\"no\",\"patch_audit_over_rsh\":\"no\",\"patch_audit_over_telnet\":\"no\",\"additional_snmp_port3\":\"161\",\"additional_snmp_port2\":\"161\",\"additional_snmp_port1\":\"161\",\"snmp_port\":\"161\",\"http_login_auth_regex_nocase\":\"no\",\"http_login_auth_regex_on_headers\":\"no\",\"http_login_invert_auth_regex\":\"no\",\"http_login_max_redir\":\"0\",\"http_reauth_delay\":\"\",\"http_login_method\":\"POST\",\"enable_admin_shares\":\"no\",\"start_remote_registry\":\"no\",\"dont_use_ntlmv1\":\"yes\",\"never_send_win_creds_in_the_clear\":\"yes\",\"attempt_least_privilege\":\"no\",\"ssh_client_banner\":\"OpenSSH_5.0\",\"ssh_port\":\"22\",\"ssh_known_hosts\":\"\",\"enable_plugin_list\":\"no\",\"audit_trail\":\"full\",\"enable_plugin_debugging\":\"no\",\"log_whole_attack\":\"no\",\"custom_find_filesystem_exclusions\":\"\",\"custom_find_filepath_exclusions\":\"\",\"max_simult_tcp_sessions_per_scan\":\"\",\"max_simult_tcp_sessions_per_host\":\"\",\"max_hosts_per_scan\":\"30\",\"max_checks_per_host\":\"5\",\"network_receive_timeout\":\"5\",\"reduce_connections_on_congestion\":\"no\",\"slice_network_addresses\":\"no\",\"stop_scan_on_disconnect\":\"no\",\"safe_checks\":\"yes\",\"advanced_mode\":\"Default\",\"display_unreachable_hosts\":\"no\",\"log_live_hosts\":\"no\",\"reverse_lookup\":\"no\",\"allow_post_scan_editing\":\"yes\",\"silent_dependencies\":\"yes\",\"report_superseded_patches\":\"yes\",\"report_verbosity\":\"Normal\",\"enum_local_users_end_uid\":\"1200\",\"enum_local_users_start_uid\":\"1000\",\"enum_domain_users_end_uid\":\"1200\",\"enum_domain_users_start_uid\":\"1000\",\"request_windows_domain_info\":\"yes\",\"scan_webapps\":\"no\",\"hydra_ldap_dn\":\"\",\"hydra_proxy_test_site\":\"\",\"hydra_web_page\":\"\",\"hydra_cisco_logon_pw\":\"\",\"hydra_win_pw_as_hash\":\"no\",\"hydra_win_account_type\":\"Local accounts\",\"hydra_client_id\":\"\",\"hydra_postgresql_db_name\":\"\",\"hydra_add_other_accounts\":\"yes\",\"hydra_exit_on_success\":\"no\",\"hydra_login_as_pw\":\"yes\",\"hydra_empty_passwords\":\"yes\",\"hydra_timeout\":\"30\",\"hydra_parallel_tasks\":\"16\",\"hydra_passwords_file\":\"\",\"hydra_logins_file\":\"\",\"hydra_always_enable\":\"no\",\"test_default_oracle_accounts\":\"no\",\"provided_creds_only\":\"yes\",\"thorough_tests\":\"no\",\"report_paranoia\":\"Normal\",\"assessment_mode\":\"Scan for all web vulnerabilities (quick)\",\"detect_ssl\":\"yes\",\"check_crl\":\"no\",\"enumerate_all_ciphers\":\"yes\",\"cert_expiry_warning_days\":\"60\",\"ssl_prob_ports\":\"Known SSL ports\",\"svc_detection_on_all_ports\":\"yes\",\"udp_scanner\":\"no\",\"syn_scanner\":\"yes\",\"syn_firewall_detection\":\"Automatic (normal)\",\"tcp_scanner\":\"no\",\"tcp_firewall_detection\":\"Automatic (normal)\",\"verify_open_ports\":\"no\",\"only_portscan_if_enum_failed\":\"yes\",\"snmp_scanner\":\"yes\",\"wmi_netstat_scanner\":\"yes\",\"ssh_netstat_scanner\":\"yes\",\"portscan_range\":\"default\",\"unscanned_closed\":\"no\",\"wol_wait_time\":\"5\",\"wol_mac_addresses\":\"\",\"scan_ot_devices\":\"no\",\"scan_netware_hosts\":\"no\",\"scan_network_printers\":\"no\",\"ping_the_remote_host\":\"yes\",\"udp_ping\":\"no\",\"icmp_ping\":\"yes\",\"icmp_ping_retries\":\"2\",\"icmp_unreach_means_host_down\":\"no\",\"tcp_ping\":\"yes\",\"tcp_ping_dest_ports\":\"built-in\",\"arp_ping\":\"yes\",\"fast_network_discovery\":\"no\",\"test_local_nessus_host\":\"yes\",\"discovery_mode\":\"Port scan (all ports)\",\"attach_report\":\"no\",\"emails\":\"\",\"filter_type\":\"and\",\"filters\":[],\"launch_now\":true,\"enabled\":false,\"live_results\":\"\",\"file_targets\":\"\",\"text_targets\":\"{{.Targets}}\",\"scanner_id\":\"1\",\"folder_id\":3,\"description\":\"\",\"name\":\"{{.Name}}\"}}"
