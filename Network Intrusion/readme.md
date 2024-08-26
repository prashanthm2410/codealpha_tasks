
# Network-Based Intrusion Detection System (NIDS) Setup

## Overview

This guide provides step-by-step instructions to set up a network-based intrusion detection system using Snort or Suricata. It includes installation, configuration, rule creation, and visualization of detected attacks using the ELK stack.

## Prerequisites

- Ubuntu/Debian-based Linux distribution
- Root or sudo privileges

## 1. Install Snort or Suricata

### Snort

1. **Download and Install Snort:**

   ```bash
   sudo apt-get update
   sudo apt-get install snort
   ```

2. **Configure Snort:**

   Edit the Snort configuration file located at `/etc/snort/snort.conf` and include your custom rules.

   ```bash
   sudo nano /etc/snort/snort.conf
   ```

   Add the following line to include your local rules:

   ```plaintext
   include $RULE_PATH/local.rules
   ```

### Suricata

1. **Download and Install Suricata:**

   ```bash
   sudo apt-get update
   sudo apt-get install suricata
   ```

2. **Configure Suricata:**

   Edit the Suricata configuration file located at `/etc/suricata/suricata.yaml` and include your custom rules.

   ```bash
   sudo nano /etc/suricata/suricata.yaml
   ```

   Ensure the `rule-files` section includes your rules file:

   ```yaml
   rule-files:
     - suricata.rules
   ```

## 2. Configure Rules

### Snort Rules

1. **Create Custom Rules:**

   Add your custom rules to the `local.rules` file located in `/etc/snort/rules/`.

   ```bash
   sudo nano /etc/snort/rules/local.rules
   ```

   Example rule:

   ```plaintext
   alert tcp any any -> any 80 (msg:"Possible web attack"; sid:1000001;)
   ```

2. **Update `snort.conf`:**

   Ensure your `snort.conf` includes the `local.rules` file.

### Suricata Rules

1. **Create Custom Rules:**

   Add your custom rules to the `suricata.rules` file located in `/etc/suricata/rules/`.

   ```bash
   sudo nano /etc/suricata/rules/suricata.rules
   ```

   Example rule:

   ```plaintext
   alert tcp any any -> any 80 (msg:"Possible web attack"; sid:1000001;)
   ```

2. **Update `suricata.yaml`:**

   Ensure your `suricata.yaml` includes your rules directory.

## 3. Start and Test Your NIDS

### Start Snort

```bash
sudo snort -A console -c /etc/snort/snort.conf
```

### Start Suricata

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

### Test Your Setup

Generate test traffic to match your rules and verify detection.

## 4. Visualize Detected Attacks Using ELK Stack

### Install ELK Stack

1. **Install Elasticsearch:**

   ```bash
   sudo apt-get install elasticsearch
   ```

2. **Install Logstash:**

   ```bash
   sudo apt-get install logstash
   ```

3. **Install Kibana:**

   ```bash
   sudo apt-get install kibana
   ```

### Configure Logstash

1. **Create Logstash Configuration File:**

   ```bash
   sudo nano /etc/logstash/conf.d/snort.conf
   ```

   Add the following content to parse Snort or Suricata logs:

   ```plaintext
   input {
     file {
       path => "/var/log/snort/alert"
       type => "snort"
     }
   }
   filter {
     # Add your filter rules here
   }
   output {
     elasticsearch {
       hosts => ["localhost:9200"]
     }
     stdout { codec => rubydebug }
   }
   ```

2. **Start Logstash:**

   ```bash
   sudo systemctl start logstash
   ```

### Configure Kibana

1. **Access Kibana:**

   Open your web browser and go to `http://localhost:5601`.

2. **Create Dashboards:**

   Use Kibana to create visualizations and dashboards to monitor detected attacks.

## 5. Respond to Suspicious Activity

### Set Up Alerts

Configure alerts in Snort or Suricata to notify you of suspicious activity. You can use tools like Swatch or Logwatch for alerting.

### Automate Responses

Implement scripts or tools to automate responses to alerts, such as blocking IP addresses or isolating affected systems.

## 6. Maintain and Update

- **Update Rules Regularly:** Keep your intrusion detection rules up-to-date.
- **Monitor Performance:** Regularly check the performance and adjust configurations as needed.

## Conclusion
