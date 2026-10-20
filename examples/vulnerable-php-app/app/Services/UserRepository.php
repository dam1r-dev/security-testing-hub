<?php
namespace App\Services;

class UserRepository
{
    public function search($term)
    {
        return \DB::select("select * from users where name like '%" . $term . "%'");
    }

    public static function findBy($column)
    {
        return \DB::select("select * from users order by " . $column);
    }
}
