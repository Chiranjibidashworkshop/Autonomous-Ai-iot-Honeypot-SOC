@echo off
setlocal
cd /d "%~dp0"
call STOP_PROJECT.bat
if exist data\events.db del /q data\events.db
if exist logs\honeypot.log del /q logs\honeypot.log
if exist logs\honeypot_stdout.log del /q logs\honeypot_stdout.log
if exist logs\honeypot_stderr.log del /q logs\honeypot_stderr.log
if exist logs\streamlit_stdout.log del /q logs\streamlit_stdout.log
if exist logs\streamlit_stderr.log del /q logs\streamlit_stderr.log
echo Showcase data reset. Run START_HERE.bat again.
endlocal
