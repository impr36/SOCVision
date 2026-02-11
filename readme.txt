steps to implement and start streamlit:-
    - Create a Virtual Environment (here venv created); Command : cmd - python -m venv venv;  PowerShell - py -m venv venv;

    - To Activate the Virtual Environment created; Command : cmd - venv\Scripts\activate ;  PowerShell - .\venv\Scripts\Activate.ps1; (if 'Activate.ps1' doesn't work in Powershell then run > Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process  )      

    - Install all the required packages; Command : pip install -r requirements.txt
    
    - To Deactivate the Virtual Environment; Command : deactivate

    - Run > streamlit run app.py

NOTE : Run Cmd as admin then do the above steps in cmd.

python.exe -m pip install --upgrade pip