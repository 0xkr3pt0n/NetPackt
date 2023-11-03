import matplotlib.pyplot as plt

class Visualization:
    #counstructor for the class takes cves as an input return diagram as an output
    def __init__(self, data):
        counted_data = self.counter(data)
        self.datarepresentation(counted_data)
    #function that recives data to count and check how much critical, meduim ....
    # a_data => argument data
    # r_data => returned data
    # this function takes a list of dictionaries
    def counter(self, a_data):
        r_data = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Unrecognized': 0,
        }
        for dicts in a_data:
            if dicts['base'] == "Low":
                r_data['Low'] += 1
            elif dicts['base'] == "Medium":
                r_data['Medium'] += 1
            elif dicts['base'] == "High":
                r_data['High'] += 1
            elif dicts['base'] == "Critical":
                r_data['Critical'] += 1
            else:
                r_data['Unrecognized'] += 1
        print(r_data)
        return r_data  # Return the counted data
    #this function visuallizes data and returns a diagram
    def datarepresentation(self, data):
        labels = data.keys()
        values = data.values()
        plt.pie(values, labels=labels, autopct='%1.1f%%')
        plt.title('Vulnerability Distribution')
        plt.show()

n = Visualization([
    {"cveid": 1, "base": "Low"},
    {"cveid": 2, "base": "Medium"},
    {"cveid": 3, "base": "Medium"},
    {"cveid": 4, "base": "Medium"},
    {"cveid": 5, "base": "High"},
    {"cveid": 6, "base": "Critical"},
])
