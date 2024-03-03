import psutil           

def check_camera_status():
    camera_on = False
    
    # Check for processes that access the camera
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if 'camera' in proc.info['name'].lower():
                camera_on = True
                break  # No need to continue checking if camera is found
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return camera_on




# Inside Camera_Check.py

# import psutil

# def check_camera_status():
#     """
#     Function to check if the camera is on or off.
#     """
#     camera_on = False
    
#     # Check for processes that access the camera
#     for proc in psutil.process_iter(['pid', 'name']):
#         try:
#             if 'camera' in proc.info['name'].lower():
#                 camera_on = True
#                 break  # No need to continue checking if camera is found
#         except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#             pass
    
#     return camera_on
