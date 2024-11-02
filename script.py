import os

# Define the path to the DriverStore FileRepository
driver_store_path = r'C:\Windows\System32\DriverStore\FileRepository'
research_list = []

# Check if the directory exists
if os.path.exists(driver_store_path):
    # Iterate through each subfolder
    os.system("mkdir H:\\research_list")
    for subfolder in os.listdir(driver_store_path):
        subfolder_path = os.path.join(driver_store_path, subfolder)

        # Check if it's actually a folder
        if os.path.isdir(subfolder_path):
            print(f"\nIn subfolder: {subfolder}")

            # Iterate through files in the subfolder
            for file in os.listdir(subfolder_path):
                # Full path to the file
                file_path = os.path.join(subfolder_path, file)

                # Check if it's a file and doesn't end with .inf
                if os.path.isfile(file_path) and not file.lower().endswith('.inf') and not file.lower().endswith('.cat'):
                    full_path = f"C:\\Windows\\System32\\DriverStore\\FileRepository\\{subfolder}\\{file}"
                    os.system(f"copy {full_path} H:\\research_list\\{subfolder}~{file}")
                    print(f"copy {full_path} H:\\research_list\\{subfolder}~{file}")
                    print(f"  {full_path}")
                    research_list.append(full_path)
    with open("H:\\research_list.txt", 'wt') as research_file:
        research_file.write("\n".join(research_list))
else:
    print(f"The path {driver_store_path} does not exist.")
