def separate_names(full_name):
    name_parts = full_name.split()


    if len(name_parts) == 1:
        return name_parts[0], "", ""
    elif len(name_parts) == 2:
        return name_parts[0], "", name_parts[1]
    else:
        first_name = name_parts[0]
        last_name = name_parts[-1]
        middle_name = " ".join(name_parts[1:-1])
        return first_name, middle_name, last_name
    

def read_and_separate_names(filename):
    separated_names = []
    with open(filename, 'r' ) as file:
        for line in file:
            name = line.strip()
            if name:
                first_name, middle_name, last_name = separate_names(name)
                separated_names.append((first_name, middle_name, last_name))
    return separated_names

def write_names_to_file(names, filename):
    #write to wriiten.txt
    with open(filename, 'w') as file:
        for first_name, middle_name, last_name in names:
            file.write(f"{first_name} {middle_name} {last_name}\n")
            

def write_first_names_to_file(names, filename):
    #write to wriiten.txt
    with open(filename, 'w') as file:
        for first_name, middle_name, last_name in names:
            file.write(f"{first_name}\n")
            
def write_last_names_to_file(names, filename):
    #write to wriiten.txt
    with open(filename, 'w') as file:
        for first_name, middle_name, last_name in names:
            file.write(f"{last_name}\n")
    
names_file = "names.txt"
separate_names = read_and_separate_names(names_file)

for first_name, middle_name, last_name in separate_names:
    print(f"First: {first_name}, Middle: {middle_name}, Last: {last_name}")
    print(f"\tFirst Name: {first_name}")
    print(f"\tMiddle Name: {middle_name}")
    print(f"\tLast Name: {last_name}")
    print("-"*20)

write_names_to_file(separate_names, "written.txt")
write_first_names_to_file(separate_names, "first_names.txt")
write_last_names_to_file(separate_names, "last_names.txt")
