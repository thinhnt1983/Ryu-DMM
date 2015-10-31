class MobilityTracker():
    

    def __init__(self,*args,**kwargs):
        #Dictionnary : one Host ID is associated to a list of datapath ID
        self.trackingDict = {}

    
    def getTraceAndUpdate(self, newHostID, newDp):
        #Checking if new Host has a Trace or not
        if newHostID not in self.trackingDict:
            self.trackingDict[newHostID] = [newDp]
        
        trace = self.trackingDict[newHostID]
        #if a router solicitation is received by the
        #same switch which the last visited too, its dpid 
        #is not appended to the list as it is the same as 
        #the last appended.
        if trace[-1].id != newDp.id:
            trace.append(newDp)
        return trace        
        
            
