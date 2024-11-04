import tkinter as tk
from tkinter import ttk
from concurrent.futures import ThreadPoolExecutor
import json
import time
import subprocess
import ipaddress
import requests
import socket
from PIL import Image, ImageTk
import threading
import re
import ssl
import urllib3
import os
import ctypes
import shutil
from threading import Timer

# Define the global lock for start_action
start_action_lock = threading.Lock()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to check if script is running with administrative privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Function to check the status of the Cisco Secure Client service
def is_service_running(service_name):
    result = subprocess.run(["sc", "query", service_name], capture_output=True, text=True)
    return "RUNNING" in result.stdout

def copy_and_modify_config(ip_address):
    """Copy only the contents of the orgConfig section, modify it with the selected IP, and save as swg_org_config.flag."""
    original_config_path = r"C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\SWG\SWGConfig.json"
    target_config_path = r"C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\data\swg_org_config.flag"
    
    # Read the original config file and extract only the orgConfig section
    with open(original_config_path, 'r') as file:
        config = json.load(file)
    
    # Extract the orgConfig content
    org_config = config.get("orgConfig", {})
    
    # Overwrite swgAnycast and swgDomain with the IP address of the selected city
    org_config["swgAnycast"] = ip_address
    org_config["swgDomain"] = ip_address  # Assuming domain uses the IP; update if needed
    
    # Save only the modified orgConfig content to the new file
    with open(target_config_path, 'w') as file:
        json.dump(org_config, file, indent=4)
    
    print(f"Copied and modified orgConfig content to {target_config_path} with IP: {ip_address}")
    
    # Ensure the csc_vpnagent service is running after modification
    start_service()

# Function to delete the swg_org_config.flag file and ensure the service is running after
def delete_modified_config():
    target_config_path = r"C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\data\swg_org_config.flag"
    original_config_path = r"C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\SWG\SWGConfig.json"

    # Delete the temporary flag file if it exists
    if os.path.exists(target_config_path):
        os.remove(target_config_path)
        print("Deleted swg_org_config.flag file.")

    # Ensure default values in SWGConfig.json with compact format
    try:
        with open(original_config_path, 'r') as file:
            config = json.load(file)
        
        # Set default values for swgAnycast and swgDomain
        config["orgConfig"]["swgAnycast"] = "146.112.255.50"
        config["orgConfig"]["swgDomain"] = "swg-url-proxy-https.sigproxy.qq.opendns.com"
        
        # Save the modified config with defaults back to SWGConfig.json in single line
        with open(original_config_path, 'w') as file:
            json.dump(config, file, separators=(',', ':'))
        
        print("Reset swgAnycast and swgDomain to default values in SWGConfig.json (single line format).")

    except Exception as e:
        print(f"Error resetting SWGConfig.json to default values: {e}")

    # Ensure the csc_vpnagent service is running after deletion
    start_service()


# Function to ping a specific IP
def ping_ip(ip):
    """Ping a given IP address and return True if successful."""
    try:
        output = subprocess.check_output(
            ['ping', '-n', '1', '-w', '300', ip],
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            creationflags=subprocess.CREATE_NO_WINDOW  # Suppress the console window
        )
        return 'TTL=' in output  # Check for successful ping response
    except subprocess.CalledProcessError:
        return False

# Function to check if port 443 is open
def is_port_open(ip, port=80):
    """Check if a specific port is open on the given IP address with a minimal timeout."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)  # Set a short timeout to speed up the check
        result = sock.connect_ex((ip, port))  # Returns 0 if the port is open
        return result == 0

# Modify the ping_city_subnet function to use the new ping and port-check logic
def ping_city_subnet(city, city_subnets):
    """Ping IPs in the city's subnet, then check if port 80 is open. Update config if conditions are met."""
    if city not in city_subnets:
        print(f"No subnet found for city: {city}")
        return None

    for subnet in city_subnets[city]:
        network = ipaddress.ip_network(subnet, strict=False)
        for ip in network.hosts():
            if ip.packed[-1] >= 171:  # Check if last octet is >= 171
                ip_str = str(ip)
                
                # Step 1: Ping the IP
                if ping_ip(ip_str):
                    print(f"Responsive IP found: {ip_str}")
                    
                    # Step 2: Check if port 80 is open
                    if is_port_open(ip_str, port=80):
                        print(f"Port 80 is open on {ip_str}. Updating configuration.")
                        
                        # Overwrite SWGConfig.json with found IP
                        copy_and_modify_config(ip_str)
                        return ip_str  # Exit after finding the first suitable IP
                    else:
                        print(f"Port 80 is closed on {ip_str}. Moving to next IP.")
    
    print("No responsive IP with port 80 open found for the city.")
    return None

# Modify the stop_action function to delete swg_org_config.flag
def stop_action():
    global countdown_id, countdown_time
    if countdown_id is not None:
        root.after_cancel(countdown_id)
        countdown_id = None
    countdown_time = 0
    timer_label.config(text="")
    stop_service()
    delete_modified_config()  # Delete the modified config file
    start_service()  # Ensure the service is started after reset
    stop_button.config(state='disabled')

# Function to stop the Cisco VPN service with error handling
def stop_service():
    if is_admin():
        if is_service_running("csc_vpnagent"):
            result = subprocess.run(["sc", "stop", "csc_vpnagent"], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Failed to stop service: {result.stderr}")
            else:
                print("VPN service stopped successfully.")
                time.sleep(5)
        else:
            print("VPN service is not running.")
    else:
        print("This script must be run with administrative privileges.")

# Function to start the Cisco VPN service with error handling
def start_service():
    if is_admin():
        if not is_service_running("csc_vpnagent"):
            result = subprocess.run(["sc", "start", "csc_vpnagent"], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Failed to start service: {result.stderr}")
            else:
                print("VPN service started successfully.")
        else:
            print("VPN service is already running.")
    else:
        print("This script must be run with administrative privileges.")

# Global variables for countdown timer
countdown_id = None
countdown_time = 180  # Countdown time in seconds
timer_running = False  # Flag to prevent multiple timers

def start_timer():
    """Start a countdown timer for reverting configurations."""
    global countdown_id, countdown_time, timer_running

    # Prevent starting the timer if it's already running
    if timer_running:
        return

    # Cancel any existing timer
    if countdown_id is not None:
        root.after_cancel(countdown_id)
        countdown_id = None

    # Set countdown time and flag
    countdown_time = 180  # Reset to 3 minutes
    timer_running = True  # Mark the timer as running
    timer_label.config(text=f"Time remaining: {countdown_time // 60}:{countdown_time % 60:02}")

    def countdown():
        global countdown_id, countdown_time, timer_running
        if countdown_time > 0:
            countdown_time -= 1
            timer_label.config(text=f"Time remaining: {countdown_time // 60}:{countdown_time % 60:02}")
            countdown_id = root.after(1000, countdown)  # Continue countdown every 1 second
        else:
            # Timer ends: stop services, delete config, restart service, and notify user
            stop_service()
            delete_modified_config()
            start_service()  # Ensure the service is started after reset
            timer_label.config(text="Timer completed, reverted to default.")
            stop_button.config(state='disabled')
            timer_running = False  # Reset the flag to stop further restarts

    countdown_id = root.after(1000, countdown)  # Start the countdown

# Fetch city subnets from the provided URL
def fetch_city_subnets():
    try:
        response = requests.get("https://geofeed.network.strln.net", timeout=10, verify=False)
        city_subnets = {}
        for line in response.text.splitlines():
            parts = line.split(',')
            if len(parts) >= 4:
                ip_prefix = parts[0]
                city_name = parts[3].strip()
                if city_name not in city_subnets:
                    city_subnets[city_name] = []
                city_subnets[city_name].append(ip_prefix)
        return city_subnets
    except requests.RequestException as e:
        print(f"Error fetching city subnets: {e}")
        return {}

def start_action():
    """Function to perform the action with thread locking."""
    # Acquire the lock to ensure this function runs exclusively
    with start_action_lock:
        selected_city = city_combobox.get()
        if selected_city:
            stop_service()
            responsive_ip = ping_city_subnet(selected_city, city_subnets)
        
            if responsive_ip:
                start_service()
                start_timer()  # Start the countdown timer after a successful response
                stop_button.config(state='normal')
            else:
                print("No responsive IP found, config not updated.")

class DNSBenchmarkingTool:
    def __init__(self, master):
        self.master = master
        self.master.title("SWG Benchmark Tool")
        self.master.configure(bg='orange')
        self.master.geometry("500x500")

        # --- SWG DC Latency Test UI ---
        latency_frame = tk.Frame(master, bg='orange')
        latency_frame.pack(pady=10)

        self.latency_button = tk.Button(latency_frame, text="SWG DC Latency", command=self.start_latency_test, bg='lightgray')
        self.latency_button.pack(side=tk.LEFT, padx=5)

        self.clear_latency_button = tk.Button(latency_frame, text="Clear", command=self.clear_latency_results, bg='lightgray')
        self.clear_latency_button.pack(side=tk.LEFT, padx=5)

        # Latency results
        self.latency_result_label = tk.Label(master, text="Latency Results will be displayed here.", bg='orange', fg='purple', font=("Arial", 10, "bold"))
        self.latency_result_label.pack(pady=10)

        # Progress bar for latency test
        self.latency_progress_frame = tk.Frame(master, bg='orange')
        self.latency_progress_frame.pack(pady=5)
        self.latency_tiles = []
        for i in range(38):
            tile = tk.Label(self.latency_progress_frame, width=1, height=0, bg='gray', relief="ridge")
            tile.grid(row=0, column=i, padx=0.1)
            self.latency_tiles.append(tile)

        # --- SWG DNS Test UI ---
        dns_frame = tk.Frame(master, bg='orange')
        dns_frame.pack(pady=(30, 0))  # Add more top padding to move DNS frame lower

        self.dns_button = tk.Button(dns_frame, text="SWG DNS Test", command=self.start_dns_test, bg='lightgray')
        self.dns_button.pack(side=tk.LEFT, padx=5)

        self.clear_dns_button = tk.Button(dns_frame, text="Clear", command=self.clear_dns_results, bg='lightgray')
        self.clear_dns_button.pack(side=tk.LEFT, padx=5)

        # Timer Label - Using place to set it lower without affecting other elements
        self.timer_label = tk.Label(self.master, text="", bg="orange", fg="purple", font=('TkDefaultFont', 12, 'bold'))
        self.timer_label.place(x=10, y=500)  # Move it to a specific y-coordinate lower in the UI

        # DNS result label setup
        self.dns_result_label = tk.Label(master, text="DNS Results will be displayed here.", bg='orange', fg='purple', font=("Arial", 10, "bold"))
        self.dns_result_label.pack(pady=10)

        # OpenDNS resolution result
        self.opendns_result_label = tk.Label(master, text="", font=("Arial", 10, "bold"), bg='orange', fg='green')
        self.opendns_result_label.pack(pady=5)

        # Cisco Logo at the bottom center
        try:
            self.logo_image = Image.open("old_cisco.png")
            self.logo_image = self.logo_image.resize((150, 50), Image.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(self.logo_image)
            self.logo_label = tk.Label(master, image=self.logo_photo, bg='orange')
            self.logo_label.pack(side=tk.BOTTOM, pady=10)
        except Exception as e:
            print(f"Error loading image: {e}")

        # Updated list of cities with SWG DCs
        self.cities_with_swg_dcs = {
            'Amsterdam': 'Netherlands',
            'Ashburn': 'United States',
            'Atlanta': 'United States',
            'Chennai': 'India',
            'Chicago': 'United States',
            'Copenhagen': 'Denmark',
            'Dallas': 'United States',
            'Denver': 'United States',
            'Dubai': 'United Arab Emirates',
            'Dublin': 'Ireland',
            'Frankfurt': 'Germany',
            'Hong Kong': 'China',
            'London': 'England',
            'Los Angeles': 'United States',
            'Madrid': 'Spain',
            'Manchester': 'England',
            'Marseille': 'France',
            'Melbourne': 'Australia',
            'Miami': 'United States',
            'Milan': 'Italy',
            'Minneapolis': 'United States',
            'Mumbai': 'India',
            'New York': 'United States',
            'Osaka': 'Japan',
            'Queretaro': 'Bajio, Mexico',
            'Paris': 'France',
            'Prague': 'Czech Republic',
            'Reston': 'United States',
            'Rio de Janeiro': 'Brazil',
            'San Jose': 'United States',
            'Sao Paulo': 'Brazil',
            'Seoul': 'South Korea',
            'Singapore': 'Singapore',
            'Stockholm': 'Sweden',
            'Sydney': 'Australia',
            'Tokyo': 'Japan',
            'Toronto': 'Canada',
            'Vancouver': 'Canada'
        }

        # Show OpenDNS resolution result upon initialization
        self.show_opendns_result()

        # Create separate executors for latency and DNS tests
        self.latency_executor = ThreadPoolExecutor(max_workers=1)
        self.dns_executor = ThreadPoolExecutor(max_workers=1)

        # Use threading locks to prevent overlapping executions
        self.latency_lock = threading.Lock()
        self.dns_lock = threading.Lock()

        # Add a flag to control the latency test
        self.latency_test_running = False
        self.latency_future = None
    def clear_latency_results(self):
        """Clear latency test results and reset text color to purple."""
        self.latency_result_label.config(text="Latency test Results will be displayed here.", font=("Arial", 10, "bold"), fg='purple')
        self.reset_latency_tiles()
        self.latency_test_running = False
        if self.latency_future and not self.latency_future.done():
            self.latency_future.cancel()

    def clear_dns_results(self):
        """Clear DNS test results and reset text color to purple."""
        self.dns_result_label.config(text="DNS test Results will be displayed here.", font=("Arial", 10, "bold"), fg='purple')

    def reset_latency_tiles(self):
        """Reset latency tiles to gray."""
        for tile in self.latency_tiles:
            tile.configure(bg='gray')
    def show_opendns_result(self):
        """Resolve DNS using OpenDNS and show the result in bold and green."""
        url = "swg-url-proxy-https.sigproxy.qq.opendns.com"
        resolvers = ["208.67.220.220", "208.67.222.222"]
        city_result = ""

        for resolver in resolvers:
            try:
                socket.setdefaulttimeout(3)
                resolved_ip = socket.gethostbyname(url)
                city_result = self.get_city_info(resolved_ip)
                break
            except socket.gaierror as e:
                print(f"Error resolving with OpenDNS: {e}")

        if city_result:
            self.opendns_result_label.config(
                text=f"SWG DC result when using OpenDNS resolver: {city_result}",
                fg='green', font=("Arial", 10, "bold")
            )
        else:
            self.opendns_result_label.config(text="Unable to resolve SWG DC using OpenDNS resolver.", font=("Arial", 10, "bold"))
    def start_latency_test(self):
        """Start the latency test in a separate thread."""
        if not self.latency_lock.locked() and not self.latency_test_running:
            self.latency_result_label.config(text="Running latency test...", font=("Arial", 10, "bold"), fg='purple')
            self.latency_test_running = True
            self.latency_future = self.latency_executor.submit(self.test_fastest_dcs)

    def test_fastest_dcs(self):
        """Test the fastest DCs by pinging them."""
        with self.latency_lock:
            valid_subnets = self.fetch_swg_ips()
            if not valid_subnets:
                self.latency_result_label.config(text="No valid DCs found for pinging.", font=("Arial", 10, "bold"), fg='purple')
                self.latency_test_running = False
                return

            fastest_city = None
            fastest_latency = float('inf')
            tested_cities = set()  # Track tested cities

            def ping_city(city):
                nonlocal fastest_city, fastest_latency
                for subnet, sub_city in valid_subnets:
                    if not self.latency_test_running:
                        return
                    if sub_city == city and city not in tested_cities:
                        print(f"Testing subnet: {subnet} for city: {city}")
                        subnet_ip = ipaddress.ip_network(subnet)
                        ip_range = [str(ip) for ip in subnet_ip.hosts() if 181 <= ip.packed[-1] <= 254]

                        consecutive_failures = 0

                        for ip in ip_range:
                            if not self.latency_test_running:
                                return
                            print(f"Pinging {ip}...")
                            ip, latency = self.ping_ip(ip)
                            if latency is not None:
                                print(f"Ping successful: {ip}, Latency: {latency} ms")
                                if latency < fastest_latency:
                                    fastest_latency = latency
                                    fastest_city = city
                                self.master.after(0, self.update_latency_tile, len(tested_cities))
                                tested_cities.add(city)  # Mark city as tested
                                break  # Stop pinging once we get a successful response

                            consecutive_failures += 1
                            if consecutive_failures >= 23:  # Stop after 23 consecutive ping failures
                                print(f"Too many failures for {city}, moving to the next subnet.")
                                break  # Move to next city if too many failures

                return False
            with ThreadPoolExecutor() as executor:
                futures = {executor.submit(ping_city, city): city for city in self.cities_with_swg_dcs.keys()}

                for future in futures:
                    future.result()

            self.latency_result_label.config(
                text=f"Closest DC: {fastest_city} with Latency: {fastest_latency:.2f} ms",
                fg='green' if fastest_city else 'purple', font=("Arial", 10, "bold")
            )
            self.latency_test_running = False
            self.master.after(0, self.update_latency_tile, len(self.latency_tiles) - 1)
    def update_latency_tile(self, index):
        """Updates the tile color to green and ensures the last tile is updated when complete."""
        if index < len(self.latency_tiles):
            self.latency_tiles[index].configure(bg='green')

    def start_dns_test(self):
        """Start the DNS test in a separate thread."""
        if not self.dns_lock.locked():
            self.dns_result_label.config(text="Running DNS test...", font=("Arial", 10, "bold"), fg='purple')
            self.dns_executor.submit(self.dns_test)
    def dns_test(self):
        """Perform DNS resolution with local DNS and print the result."""
        with self.dns_lock:
            url = "swg-url-proxy-https.sigproxy.qq.opendns.com"
            local_dns_city = None

            # Check local DNS configuration
            try:
                resolved_ip = socket.gethostbyname(url)
                local_dns_city = self.get_city_info(resolved_ip)
            except socket.gaierror as e:
                print(f"Error resolving with local DNS: {e}")

            result_text = ""
            if local_dns_city:
                result_text += f"Best SWG DC according to your local DNS: {local_dns_city}"
            else:
                result_text += "Cannot find SWG DC with local DNS."

            self.dns_result_label.config(text=result_text, fg='green', font=("Arial", 10, "bold"))
    def get_city_info(self, ip):
        """Fetch city information based on the first three octets of the resolved IP."""
        ip_prefix = '.'.join(ip.split('.')[:3])  # Only use the first three octets
        city_mapping = self.fetch_city_data()  # Fetch city data
        return city_mapping.get(ip_prefix, None)

    def fetch_swg_ips(self):
        """Fetch the SWG DC subnets."""
        try:
            response = requests.get("https://geofeed.network.strln.net", timeout=10, verify=False)
            valid_subnets = []
            for line in response.text.splitlines():
                parts = line.split(',')
                subnet = parts[0]
                city = parts[3] if len(parts) > 3 else ''
                if self.is_valid_subnet(subnet, city):
                    valid_subnets.append((subnet, city))
                    print(f"Valid Subnet Added: {subnet}, City={city}")
            return valid_subnets
        except requests.RequestException as e:
            print(f"Error fetching SWG IPs: {e}")
            return []

    def is_valid_subnet(self, subnet, city):
        """Check if the subnet is valid and corresponds to a city with SWG DC."""
        try:
            first_octet = int(subnet.split('.')[0])
            return 146 <= first_octet <= 155 and city in self.cities_with_swg_dcs
        except ValueError:
            return False
    def ping_ip(self, ip):
        """Ping a given IP address and return the latency if successful."""
        command = ['ping', '-n', '1', '-w', '300', ip]  # Adjusted for Windows: -n for number of pings, -w for timeout in ms
        try:
            # Adding the creationflags to suppress the console window on Windows
            output = subprocess.check_output(
                command, 
                stderr=subprocess.STDOUT, 
                universal_newlines=True,
                creationflags=subprocess.CREATE_NO_WINDOW  # Suppress the console window
            )
            latency_match = re.search(r'time[=<](\d+)', output)
            if latency_match:
                latency = float(latency_match.group(1))
                return ip, latency
            return ip, None
        except subprocess.CalledProcessError as e:
            print(f"Ping failed for {ip}: {e}")
            return ip, None

    def fetch_city_data(self):
        """Fetch and parse city data from the SWG DC list."""
        try:
            response = requests.get("https://geofeed.network.strln.net", timeout=10, verify=False)
            city_mapping = {}
            for line in response.text.splitlines():
                parts = line.split(',')
                if len(parts) >= 4:
                    ip_prefix = '.'.join(parts[0].split('.')[:3])  # Get the first three octets of the subnet
                    city_name = parts[3]  # Get the city name (last part)
                    city_mapping[ip_prefix] = city_name  # Map the IP prefix to the city name
            return city_mapping
        except requests.RequestException as e:
            print(f"Error fetching city data: {e}")
            return {}
# Function to start the timer
countdown_id = None  # Global variable to store the after() id
countdown_time = 180  # Global variable for countdown time

def start_timer():
    global countdown_id, countdown_time
    countdown_time = 180  # 3 minutes in seconds
    timer_label.config(text=f"Time remaining: {countdown_time // 60}:{countdown_time % 60:02}")
    def countdown():
        global countdown_id, countdown_time
        if countdown_time > 0:
            countdown_time -= 1
            timer_label.config(text=f"Time remaining: {countdown_time // 60}:{countdown_time % 60:02}")
            countdown_id = root.after(1000, countdown)
        else:
            stop_service()
            delete_modified_config()  # Delete the modified config file
            start_service()
            timer_label.config(text="Timer completed, reverted to default.")
            stop_button.config(state='disabled')
    countdown_id = root.after(1000, countdown)

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSBenchmarkingTool(root)
    
    # Additional UI elements after initializing the main application
    latency_test_label = tk.Label(root, text="Do not exit program before the last test is finished, or click on STOP.", bg="orange", fg="purple", font=('TkDefaultFont', 10, 'bold'))
    latency_test_label.place(relx=0.5, y=340, anchor='center')

    # Drop-down list of cities
    cities = [
        'Amsterdam', 'Ashburn', 'Atlanta', 'Chennai', 'Chicago', 'Copenhagen', 'Dallas', 'Denver', 
	    'Dubai', 'Dublin', 'Frankfurt', 'Hong Kong', 'London', 'Los Angeles', 'Madrid', 'Manchester', 
	    'Marseille', 'Melbourne', 'Miami', 'Milan', 'Minneapolis', 'Mumbai', 'New York', 'Osaka', 
	    'Queretaro', 'Paris', 'Prague', 'Reston', 'Rio de Janeiro', 'San Jose', 'Sao Paulo', 'Seoul', 
	    'Singapore', 'Stockholm', 'Sydney', 'Tokyo', 'Toronto', 'Vancouver'
    ]
    city_combobox = ttk.Combobox(root, values=cities)
    city_combobox.set("Select a city")
    city_combobox.place(relx=0.5, y=370, anchor='center')

    # Fetch subnets upon application start
    city_subnets = fetch_city_subnets()

	# Start and Stop button setup
    button_frame = tk.Frame(root, bg="orange")
    button_frame.place(relx=0.5, y=410, anchor='center')
    start_button = tk.Button(button_frame, text="Start", command=start_action)
    start_button.pack(side='left', padx=10)
    stop_button = tk.Button(button_frame, text="Stop", command=stop_action, state='disabled')
    stop_button.pack(side='left', padx=10)

	# Timer label
    timer_label = tk.Label(root, text="", bg="orange", fg="purple", font=('TkDefaultFont', 12, 'bold'))
    timer_label.place(x=10, y=500)

    # Timer Label - move this above the DNS result label
    timer_label = tk.Label(root, text="", bg="orange", fg="purple", font=('TkDefaultFont', 12, 'bold'))
    timer_label.pack()  # Ensure this line is before dns_result_label for correct placement

    root.mainloop()
