:5000 {
	encode zstd gzip
	reverse_proxy {
		# Every replica of the registry service, re-resolved as replicas come and go.
		dynamic a {
			name registry
			port 5000
			refresh 10s
		}
		lb_policy round_robin
		health_uri /readyz
		health_interval 10s
		health_timeout 5s
		# Large layer uploads: don't buffer them, don't time out.
		flush_interval -1
		transport http {
			read_timeout 0
			write_timeout 0
		}
	}
}
