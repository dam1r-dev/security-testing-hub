<?php
namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function show($slug)
    {
        return DB::select("select * from users where slug = '$slug'");   // SQL injection: $slug is the caller's
    }

    public function find(int $id)
    {
        return DB::select("select * from users where id = $id");   // safe: the int type converts it
    }

    public function store(Request $request)
    {
        return User::create($request->all());   // mass assignment
    }

    public function search(Request $request)
    {
        return DB::table('users')->whereRaw("name like '%" . $request->input('q') . "%'")->get();   // SQL injection
    }

    public function safe(Request $request)
    {
        return User::create($request->only(['name', 'email']));   // safe
    }
}
