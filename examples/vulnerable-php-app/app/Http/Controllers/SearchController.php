<?php
namespace App\Http\Controllers;

use App\Services\UserRepository;
use Illuminate\Http\Request;

class SearchController extends Controller
{
    public function __construct(private UserRepository $users)
    {
    }

    public function index(Request $request)
    {
        return $this->users->search($request->input('q'));   // SQL injection in another file
    }

    public function sorted(Request $request)
    {
        return UserRepository::findBy($request->input('by'));   // a static method of an imported class
    }
}
